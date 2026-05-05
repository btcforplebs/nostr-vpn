import AppKit
import CoreImage
import SwiftUI

struct RootView: View {
    @ObservedObject var manager: AppManager

    @State private var nodeName = ""
    @State private var endpoint = ""
    @State private var tunnelIp = ""
    @State private var listenPort = ""
    @State private var magicDnsSuffix = ""
    @State private var advertisedRoutes = ""
    @State private var relayInput = ""
    @State private var participantInput = ""
    @State private var participantAliasInput = ""
    @State private var networkNameInput = ""
    @State private var exitNodeSearch = ""
    @State private var networkNameDrafts: [String: String] = [:]
    @State private var networkMeshDrafts: [String: String] = [:]
    @State private var participantAliasDrafts: [String: String] = [:]
    @State private var diagnosticsExpanded = false
    @State private var savedExpanded = true
    @State private var showingQrScanner = false
    @State private var selectedSidebarItem: SidebarItem? = .overview
    @State private var lastSyncedRev: UInt64 = 0

    private var state: NativeAppState {
        manager.state
    }

    private var activeNetwork: NativeNetworkState? {
        manager.activeNetwork
    }

    var body: some View {
        NavigationSplitView {
            sidebar
        } detail: {
            detailPane
        }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button {
                    manager.refresh()
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
                .disabled(manager.actionInFlight)
            }
        }
        .onAppear(perform: syncDrafts)
        .onChange(of: state.rev) { _, _ in
            syncDrafts()
        }
        .onChange(of: state.health.count) { oldValue, newValue in
            if newValue > oldValue {
                diagnosticsExpanded = true
            }
        }
        .sheet(isPresented: $showingQrScanner) {
            QRCodeScannerSheet { code in
                manager.importInvite(code)
                showingQrScanner = false
            }
        }
    }

    private var sidebar: some View {
        List(selection: $selectedSidebarItem) {
            Section {
                sidebarItem(.overview, "Status", "power")
                sidebarItem(.devices, "Devices", "desktopcomputer")
                sidebarItem(.sharing, "Invite", "qrcode")
                sidebarItem(.routing, "Exit Nodes", "arrow.triangle.branch")
                sidebarItem(.networks, "Networks", "rectangle.stack")
                sidebarItem(.deviceSettings, "Device", "macwindow")
                sidebarItem(.service, "Service", "gearshape.2")
                sidebarItem(.updates, "Updates", "arrow.triangle.2.circlepath")
                sidebarItem(.cli, "CLI", "terminal")
                sidebarItem(.relays, "Relays", "antenna.radiowaves.left.and.right")
                sidebarItem(.diagnostics, "Diagnostics", "waveform.path.ecg")
            }

            Section {
                HStack {
                    TextField("Name", text: $networkNameInput)
                    Button {
                        manager.addNetwork(networkNameInput)
                        networkNameInput = ""
                    } label: {
                        Image(systemName: "plus")
                    }
                    .buttonStyle(.borderless)
                    .disabled(networkNameInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || manager.actionInFlight)
                }
            }
        }
        .navigationSplitViewColumnWidth(min: 210, ideal: 230)
    }

    private func sidebarItem(_ item: SidebarItem, _ title: String, _ systemImage: String) -> some View {
        Label(title, systemImage: systemImage)
            .tag(item)
    }

    private var detailPane: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                switch selectedSidebarItem ?? .overview {
                case .overview:
                    heroSection
                    if let activeNetwork {
                        activeNetworkSection(activeNetwork)
                    }
                case .devices:
                    pageTitle("Devices", "desktopcomputer")
                    if let activeNetwork {
                        participantsSection(activeNetwork)
                    }
                case .sharing:
                    pageTitle("Invite", "qrcode")
                    if let activeNetwork {
                        inviteSection(activeNetwork)
                    }
                case .routing:
                    pageTitle("Exit Nodes", "arrow.triangle.branch")
                    if let activeNetwork {
                        routingSection(activeNetwork)
                    }
                case .networks:
                    pageTitle("Networks", "rectangle.stack")
                    savedNetworksSection
                case .deviceSettings:
                    pageTitle("Device", "macwindow")
                    deviceSettings
                case .service:
                    pageTitle("Service", "gearshape.2")
                    serviceControls
                case .updates:
                    pageTitle("Updates", "arrow.triangle.2.circlepath")
                    updateControls
                case .cli:
                    pageTitle("CLI", "terminal")
                    cliControls
                case .relays:
                    pageTitle("Relays", "antenna.radiowaves.left.and.right")
                    relaySection
                case .diagnostics:
                    pageTitle("Diagnostics", "waveform.path.ecg")
                    diagnosticsSection
                }
            }
            .padding(.horizontal, 24)
            .padding(.top, 24)
            .padding(.bottom, 28)
            .frame(maxWidth: 980, alignment: .leading)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }

    private func pageTitle(_ title: String, _ systemImage: String) -> some View {
        Label(title, systemImage: systemImage)
            .font(.system(size: 28, weight: .semibold))
    }

    private var heroSection: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .top, spacing: 18) {
                VStack(alignment: .leading, spacing: 6) {
                    Text(activeNetwork.map(displayName) ?? "Nostr VPN")
                        .font(.system(size: 32, weight: .semibold))
                    HStack(spacing: 8) {
                        if activeNetwork?.localIsAdmin == true {
                            badge("Admin", style: .ok)
                        }
                        badge(heroBadgeText, style: state.meshReady ? .ok : state.sessionActive ? .warn : .muted)
                    }
                    Text(heroSubtext)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button {
                    manager.toggleSession()
                } label: {
                    Label(
                        state.sessionActive ? "VPN On" : "VPN Off",
                        systemImage: state.sessionActive ? "power.circle.fill" : "power.circle"
                    )
                }
                .controlSize(.large)
                .buttonStyle(.borderedProminent)
                .disabled(manager.actionInFlight || !state.vpnSessionControlSupported)
            }

            if shouldShowVpnDisclosure {
                Text("VPN data: public key, membership, endpoints, relays, and counters are used only to run the VPN you configure. Packet traffic is encrypted.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }

            LazyVGrid(columns: [GridItem(.adaptive(minimum: 180), alignment: .leading)], alignment: .leading, spacing: 12) {
                metric("Daemon", state.daemonRunning ? "Running" : "Stopped")
                metric("VPN", state.sessionActive ? "On" : "Off")
                metric("FIPS", state.relayConnected ? "Ready" : "Idle")
                metric("Peers", "\(state.connectedPeerCount)/\(state.expectedPeerCount)")
                metric("Tunnel", state.tunnelIp.isEmpty ? "-" : state.tunnelIp)
                metric("Exit", selectedExitText)
            }

            HStack(spacing: 10) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Identity")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text(state.ownNpub.isEmpty ? "-" : state.ownNpub)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .textSelection(.enabled)
                }
                Spacer()
                copyButton(value: state.ownNpub, copied: .pubkey, systemImage: "person.crop.circle")
                    .disabled(state.ownNpub.isEmpty)
            }

            if !state.error.isEmpty || !manager.actionStatus.isEmpty {
                Label(state.error.isEmpty ? manager.actionStatus : state.error, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(state.error.isEmpty ? Color.secondary : Color.orange)
                    .textSelection(.enabled)
            }
        }
    }

    private func activeNetworkSection(_ network: NativeNetworkState) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            sectionHeader("Active Network", systemImage: "point.3.connected.trianglepath.dotted")
            Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 10) {
                GridRow {
                    label("Name")
                    TextField("Name", text: networkNameBinding(network))
                    Button {
                        manager.renameNetwork(networkId: network.id, name: networkNameDrafts[network.id] ?? network.name)
                    } label: {
                        Image(systemName: "checkmark")
                    }
                    .disabled(!network.localIsAdmin || manager.actionInFlight)
                }
                GridRow {
                    label("Mesh ID")
                    TextField("Mesh ID", text: networkMeshBinding(network))
                    Button {
                        manager.setNetworkMeshId(networkId: network.id, meshId: networkMeshDrafts[network.id] ?? network.networkId)
                    } label: {
                        Image(systemName: "checkmark")
                    }
                    .disabled(!network.localIsAdmin || manager.actionInFlight)
                    copyButton(value: network.networkId, copied: .meshId, systemImage: "doc.on.doc")
                }
                GridRow {
                    label("Admins")
                    Text(adminSummary(network))
                        .foregroundStyle(.secondary)
                }
                GridRow {
                    label("Join")
                    Toggle("", isOn: Binding(
                        get: { network.joinRequestsEnabled },
                        set: { manager.setJoinRequests(networkId: network.id, enabled: $0) }
                    ))
                    .labelsHidden()
                    .disabled(!network.localIsAdmin || manager.actionInFlight)
                    Text(network.joinRequestsEnabled ? "Listening" : "Closed")
                        .foregroundStyle(.secondary)
                }
            }

            if !network.inboundJoinRequests.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Join Requests")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                    ForEach(network.inboundJoinRequests, id: \.requesterPubkeyHex) { request in
                        HStack(spacing: 10) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(request.requesterNodeName.isEmpty ? "Pending device" : request.requesterNodeName)
                                Text("\(request.requesterNpub) - \(request.requestedAtText)")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                            }
                            Spacer()
                            copyButton(value: request.requesterNpub, copied: .peerNpub, peerNpub: request.requesterNpub, systemImage: "doc.on.doc")
                            Button {
                                manager.acceptJoinRequest(networkId: network.id, requesterNpub: request.requesterNpub)
                            } label: {
                                Label("Accept", systemImage: "checkmark.circle")
                            }
                            .disabled(!network.localIsAdmin || manager.actionInFlight)
                        }
                    }
                }
            }

            inviteSection(network)
        }
    }

    private func inviteSection(_ network: NativeNetworkState) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .top, spacing: 14) {
                InviteQRCodeView(invite: state.activeNetworkInvite)
                    .frame(width: 132, height: 132)
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        Text(state.activeNetworkInvite.isEmpty ? "No invite" : state.activeNetworkInvite)
                            .lineLimit(1)
                            .truncationMode(.middle)
                            .textSelection(.enabled)
                            .padding(.horizontal, 10)
                            .frame(height: 32)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 6))
                        copyButton(value: state.activeNetworkInvite, copied: .invite, systemImage: "doc.on.doc")
                            .disabled(state.activeNetworkInvite.isEmpty)
                        Button {
                            manager.share(state.activeNetworkInvite)
                        } label: {
                            Image(systemName: "square.and.arrow.up")
                        }
                        .disabled(state.activeNetworkInvite.isEmpty)
                    }
                    HStack {
                        TextField("nvpn://invite/...", text: $manager.inviteInput)
                            .onSubmit {
                                manager.importInvite(manager.inviteInput)
                            }
                        Button {
                            manager.importInvite(manager.inviteInput)
                        } label: {
                            Label("Import", systemImage: "square.and.arrow.down")
                        }
                        Button {
                            showingQrScanner = true
                        } label: {
                            Label("Scan", systemImage: "camera.viewfinder")
                        }
                        Button {
                            manager.chooseInviteQrImage()
                        } label: {
                            Label("Image", systemImage: "qrcode.viewfinder")
                        }
                    }
                    HStack {
                        Button {
                            manager.startLanPairing()
                        } label: {
                            Label(
                                state.lanPairingActive ? "Pairing \(formatSeconds(state.lanPairingRemainingSecs))" : "LAN Pair",
                                systemImage: "dot.radiowaves.left.and.right"
                            )
                        }
                        .disabled(manager.actionInFlight)
                        Button {
                            manager.stopLanPairing()
                        } label: {
                            Label("Stop", systemImage: "stop.circle")
                        }
                        .disabled(!state.lanPairingActive || manager.actionInFlight)
                        if network.outboundJoinRequest != nil {
                            badge("Join requested", style: .warn)
                        } else if !network.inviteInviterNpub.isEmpty {
                            Button {
                                manager.requestNetworkJoin(networkId: network.id)
                            } label: {
                                Label("Request Join", systemImage: "person.badge.plus")
                            }
                            .disabled(manager.actionInFlight)
                        }
                    }
                }
            }

            if !state.lanPeers.isEmpty {
                ForEach(state.lanPeers, id: \.invite) { peer in
                    HStack {
                        Text(peer.nodeName.isEmpty ? peer.npub : peer.nodeName)
                        Text(peer.networkName)
                            .foregroundStyle(.secondary)
                        Spacer()
                        Button {
                            manager.importInvite(peer.invite)
                        } label: {
                            Label("Join", systemImage: "plus.circle")
                        }
                    }
                }
            }
        }
    }

    private func participantsSection(_ network: NativeNetworkState) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            sectionHeader("Devices", systemImage: "desktopcomputer")
            if network.participants.isEmpty {
                Text("No devices")
                    .foregroundStyle(.secondary)
            } else {
                ForEach(network.participants, id: \.pubkeyHex) { participant in
                    participantRow(participant, network: network)
                }
            }
            HStack {
                TextField("Participant npub", text: $participantInput)
                    .onSubmit(addParticipantToActiveNetwork)
                TextField("Alias", text: $participantAliasInput)
                    .frame(maxWidth: 180)
                    .onSubmit(addParticipantToActiveNetwork)
                Button {
                    addParticipantToActiveNetwork()
                } label: {
                    Label("Add", systemImage: "plus")
                }
                .disabled(!network.localIsAdmin || participantInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || manager.actionInFlight)
            }
        }
    }

    private func participantRow(_ participant: NativeParticipantState, network: NativeNetworkState) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: participant.reachable ? "checkmark.circle.fill" : "circle")
                .foregroundStyle(participant.reachable ? .green : .secondary)
                .padding(.top, 3)
            VStack(alignment: .leading, spacing: 5) {
                HStack {
                    TextField("Alias", text: participantAliasBinding(participant))
                        .frame(maxWidth: 220)
                        .disabled(!network.localIsAdmin)
                    if !state.magicDnsSuffix.isEmpty {
                        Text(".\(state.magicDnsSuffix)")
                            .foregroundStyle(.secondary)
                    }
                    Button {
                        manager.setParticipantAlias(
                            npub: participant.npub,
                            alias: participantAliasDrafts[participant.pubkeyHex] ?? participant.magicDnsAlias
                        )
                    } label: {
                        Image(systemName: "checkmark")
                    }
                    .disabled(!network.localIsAdmin || manager.actionInFlight)
                }
                Text(participant.npub)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
                Text(participantDetail(participant))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 6) {
                HStack(spacing: 6) {
                    badge(transportBadgeText(participant), style: badgeStyle(for: participant.state))
                    badge(presenceBadgeText(participant), style: badgeStyle(for: participant.presenceState))
                    if participant.isAdmin {
                        badge("Admin", style: .ok)
                    }
                    if participant.offersExitNode {
                        badge("Exit", style: .warn)
                    }
                }
                HStack {
                    copyButton(value: participant.npub, copied: .peerNpub, peerNpub: participant.npub, systemImage: "doc.on.doc")
                    Button {
                        manager.toggleAdmin(networkId: network.id, participant: participant)
                    } label: {
                        Image(systemName: participant.isAdmin ? "star.slash" : "star")
                    }
                    .disabled(!network.localIsAdmin || manager.actionInFlight)
                    Button {
                        manager.removeParticipant(networkId: network.id, npub: participant.npub)
                    } label: {
                        Image(systemName: "trash")
                    }
                    .disabled(!network.localIsAdmin || manager.actionInFlight)
                }
            }
        }
        .padding(.vertical, 6)
    }

    private func routingSection(_ network: NativeNetworkState) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            sectionHeader("Routing", systemImage: "arrow.triangle.branch")
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 240), alignment: .leading)], alignment: .leading, spacing: 12) {
                Toggle("Offer private exit", isOn: Binding(
                    get: { state.advertiseExitNode },
                    set: { manager.setAdvertiseExitNode($0) }
                ))
                .disabled(manager.actionInFlight)
                VStack(alignment: .leading, spacing: 6) {
                    Text("Advertised Routes")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    HStack {
                        TextField("10.0.0.0/24, 192.168.0.0/24", text: $advertisedRoutes)
                        Button {
                            manager.setAdvertisedRoutes(advertisedRoutes)
                        } label: {
                            Image(systemName: "checkmark")
                        }
                        .disabled(manager.actionInFlight)
                    }
                }
            }

            TextField("Search exit nodes", text: $exitNodeSearch)
                .textFieldStyle(.roundedBorder)

            ScrollView(.horizontal) {
                HStack(alignment: .top, spacing: 10) {
                    Button {
                        manager.setExitNode("")
                    } label: {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("No exit node")
                            Text("Direct mesh")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        .frame(width: 160, alignment: .leading)
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.large)

                    ForEach(exitNodeCandidates(network), id: \.pubkeyHex) { participant in
                        Button {
                            manager.setExitNode(participant.npub)
                        } label: {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(participant.magicDnsName.isEmpty ? participant.alias : participant.magicDnsName)
                                    .lineLimit(1)
                                Text(participant.offersExitNode ? participant.statusText : "not offered")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            .frame(width: 180, alignment: .leading)
                        }
                        .buttonStyle(.bordered)
                        .disabled(!participant.offersExitNode || manager.actionInFlight)
                    }
                }
                .padding(.vertical, 2)
            }
        }
    }

    private var savedNetworksSection: some View {
        DisclosureGroup(isExpanded: $savedExpanded) {
            VStack(alignment: .leading, spacing: 12) {
                if manager.inactiveNetworks.isEmpty {
                    Text("No saved networks")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(manager.inactiveNetworks, id: \.id) { network in
                        savedNetworkCard(network)
                    }
                }
            }
            .padding(.top, 10)
        } label: {
            sectionHeader("Saved Networks", systemImage: "rectangle.stack")
        }
    }

    private func savedNetworkCard(_ network: NativeNetworkState) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                TextField("Name", text: networkNameBinding(network))
                Button {
                    manager.renameNetwork(networkId: network.id, name: networkNameDrafts[network.id] ?? network.name)
                } label: {
                    Image(systemName: "checkmark")
                }
                Button {
                    manager.setNetworkEnabled(networkId: network.id, enabled: true)
                } label: {
                    Label("Activate", systemImage: "arrow.right.circle")
                }
                Button {
                    manager.removeNetwork(network.id)
                } label: {
                    Image(systemName: "trash")
                }
                .disabled(manager.actionInFlight)
            }
            HStack {
                TextField("Mesh ID", text: networkMeshBinding(network))
                Button {
                    manager.setNetworkMeshId(networkId: network.id, meshId: networkMeshDrafts[network.id] ?? network.networkId)
                } label: {
                    Image(systemName: "checkmark")
                }
                Text("\(network.onlineCount)/\(network.expectedCount)")
                    .foregroundStyle(.secondary)
            }
            if !network.participants.isEmpty {
                ForEach(network.participants.prefix(4), id: \.pubkeyHex) { participant in
                    HStack {
                        Text(participant.alias)
                        Text(participant.npub)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Spacer()
                        Button {
                            manager.removeParticipant(networkId: network.id, npub: participant.npub)
                        } label: {
                            Image(systemName: "trash")
                        }
                    }
                }
            }
        }
        .padding(12)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
    }

    private var diagnosticsSection: some View {
        DisclosureGroup(isExpanded: $diagnosticsExpanded) {
            VStack(alignment: .leading, spacing: 12) {
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 190), alignment: .leading)], alignment: .leading, spacing: 10) {
                    metric("Interface", state.network.defaultInterface.isEmpty ? "unknown" : state.network.defaultInterface)
                    metric("IPv4", state.network.primaryIpv4.isEmpty ? "-" : state.network.primaryIpv4)
                    metric("IPv6", state.network.primaryIpv6.isEmpty ? "-" : state.network.primaryIpv6)
                    metric("Gateway", firstNonEmpty(state.network.gatewayIpv4, state.network.gatewayIpv6, fallback: "unknown"))
                    metric("Captive", state.network.captivePortal)
                    metric("Mapping", state.portMapping.activeProtocol.isEmpty ? "none" : state.portMapping.activeProtocol)
                    metric("External", state.portMapping.externalEndpoint.isEmpty ? "stun/direct" : state.portMapping.externalEndpoint)
                }
                if state.health.isEmpty {
                    Text("No health warnings")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(state.health, id: \.code) { issue in
                        HStack(alignment: .top) {
                            badge(issue.severity, style: healthStyle(issue.severity))
                            VStack(alignment: .leading) {
                                Text(issue.summary)
                                Text(issue.detail)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            }
            .padding(.top, 10)
        } label: {
            sectionHeader("Diagnostics", systemImage: "waveform.path.ecg")
        }
    }

    private var relaySection: some View {
        VStack(alignment: .leading, spacing: 12) {
            sectionHeader("FIPS Discovery", systemImage: "antenna.radiowaves.left.and.right")
            HStack {
                badge("\(state.relaySummary.up) up", style: .ok)
                badge("\(state.relaySummary.down) down", style: .bad)
                badge("\(state.relaySummary.unknown) unknown", style: .muted)
            }
            ForEach(state.relays, id: \.url) { relay in
                HStack {
                    Image(systemName: relay.state == "up" ? "checkmark.circle.fill" : "circle")
                        .foregroundStyle(relay.state == "up" ? .green : .secondary)
                    Text(relay.url)
                        .textSelection(.enabled)
                    Spacer()
                    Text(relay.statusText)
                        .foregroundStyle(.secondary)
                    Button {
                        manager.removeRelay(relay.url)
                    } label: {
                        Image(systemName: "trash")
                    }
                    .buttonStyle(.borderless)
                    .disabled(state.relays.count <= 1 || manager.actionInFlight)
                }
            }
            HStack {
                TextField("Relay URL", text: $relayInput)
                    .onSubmit(addRelay)
                Button {
                    addRelay()
                } label: {
                    Label("Add", systemImage: "plus")
                }
                .disabled(relayInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || manager.actionInFlight)
            }
        }
    }

    private var serviceControls: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                badge(state.serviceInstalled ? "Installed" : "Not installed", style: state.serviceInstalled ? .ok : .warn)
                badge(state.serviceRunning ? "Running" : "Stopped", style: state.serviceRunning ? .ok : .muted)
                if state.serviceDisabled {
                    badge("Disabled", style: .bad)
                }
                if manager.serviceRepairRecommended {
                    badge("Repair", style: .warn)
                }
                if manager.serviceSettling {
                    ProgressView()
                        .controlSize(.small)
                    badge("Settling", style: .muted)
                }
            }
            Text(manager.serviceRepairRecommended ? "\(state.serviceStatusDetail) · service \(state.serviceBinaryVersion), app \(state.appVersion)" : state.serviceStatusDetail)
                .font(.caption)
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
            HStack {
                Button {
                    manager.installService()
                } label: {
                    Label(serviceInstallButtonTitle, systemImage: manager.serviceRepairRecommended ? "wrench.and.screwdriver" : "arrow.down.to.line")
                }
                Button {
                    state.serviceDisabled ? manager.enableService() : manager.disableService()
                } label: {
                    Label(state.serviceDisabled ? "Enable" : "Disable", systemImage: state.serviceDisabled ? "play" : "pause")
                }
                .disabled(!state.serviceInstalled || manager.actionInFlight)
                Button {
                    manager.uninstallService()
                } label: {
                    Label("Uninstall", systemImage: "trash")
                }
                .disabled(!state.serviceInstalled || manager.actionInFlight)
            }
            .disabled(!state.serviceSupported || manager.actionInFlight || manager.serviceSettling)
        }
    }

    private var updateControls: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                badge(manager.updateAvailable ? "Update \(manager.updateVersion)" : "Current", style: manager.updateAvailable ? .warn : .ok)
                if manager.updateChecking {
                    ProgressView()
                        .controlSize(.small)
                    badge("Checking", style: .muted)
                }
                if manager.updateInstalling {
                    ProgressView()
                        .controlSize(.small)
                    badge("Installing", style: .muted)
                }
            }
            if !manager.updateStatus.isEmpty {
                Text(manager.updateStatus)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
            HStack {
                Button {
                    manager.checkForUpdates()
                } label: {
                    Label("Check Updates", systemImage: "arrow.triangle.2.circlepath")
                }
                .disabled(manager.updateChecking || manager.updateInstalling)
                Button {
                    manager.installUpdate()
                } label: {
                    Label("Install Update", systemImage: "square.and.arrow.down")
                }
                .disabled(!manager.updateAvailable || manager.updateInstalling)
                Toggle("Auto-check", isOn: $manager.autoCheckUpdates)
                Toggle("Auto-install", isOn: $manager.autoInstallUpdates)
            }
        }
    }

    private var cliControls: some View {
        HStack {
            badge(state.cliInstalled ? "CLI installed" : "CLI missing", style: state.cliInstalled ? .ok : .warn)
            Button {
                manager.installCli()
            } label: {
                Label(state.cliInstalled ? "Reinstall CLI" : "Install CLI", systemImage: "terminal")
            }
            Button {
                manager.uninstallCli()
            } label: {
                Label("Uninstall CLI", systemImage: "trash")
            }
            .disabled(!state.cliInstalled || manager.actionInFlight)
        }
        .disabled(!state.cliInstallSupported || manager.actionInFlight)
    }

    private var deviceSettings: some View {
        VStack(alignment: .leading, spacing: 10) {
            Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 10) {
                GridRow {
                    label("Name")
                    TextField("Name", text: $nodeName)
                }
                GridRow {
                    label("Endpoint")
                    TextField("Endpoint", text: $endpoint)
                }
                GridRow {
                    label("Tunnel IP")
                    TextField("Tunnel IP", text: $tunnelIp)
                }
                GridRow {
                    label("Listen Port")
                    TextField("Listen Port", text: $listenPort)
                }
                GridRow {
                    label("DNS Suffix")
                    TextField("DNS Suffix", text: $magicDnsSuffix)
                }
            }
            HStack {
                Toggle("Autoconnect", isOn: Binding(
                    get: { state.autoconnect },
                    set: { manager.setAutoconnect($0) }
                ))
                Toggle("Launch on startup", isOn: Binding(
                    get: { state.launchOnStartup },
                    set: { manager.setLaunchOnStartup($0) }
                ))
                .disabled(!state.startupSettingsSupported)
                Toggle("Menu bar on close", isOn: Binding(
                    get: { state.closeToTrayOnClose },
                    set: { manager.setCloseToTray($0) }
                ))
                .disabled(!state.trayBehaviorSupported)
            }
            Button {
                manager.saveNodeSettings(
                    nodeName: nodeName,
                    endpoint: endpoint,
                    tunnelIp: tunnelIp,
                    listenPort: listenPort,
                    magicDnsSuffix: magicDnsSuffix
                )
            } label: {
                Label("Save Device", systemImage: "checkmark")
            }
            .disabled(manager.actionInFlight)
        }
    }

    private func sectionHeader(_ title: String, systemImage: String) -> some View {
        Label(title, systemImage: systemImage)
            .font(.headline)
    }

    private func label(_ text: String) -> some View {
        Text(text)
            .foregroundStyle(.secondary)
            .frame(width: 90, alignment: .leading)
    }

    private func metric(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(value.isEmpty ? "-" : value)
                .font(.subheadline.weight(.medium))
                .lineLimit(1)
                .truncationMode(.middle)
                .textSelection(.enabled)
        }
    }

    private func badge(_ text: String, style: BadgeStyle) -> some View {
        Text(text)
            .font(.caption.weight(.semibold))
            .padding(.horizontal, 7)
            .padding(.vertical, 3)
            .foregroundStyle(style.foreground)
            .background(style.background, in: RoundedRectangle(cornerRadius: 6))
    }

    private func copyButton(
        value: String,
        copied: CopyValue,
        peerNpub: String? = nil,
        systemImage: String
    ) -> some View {
        Button {
            manager.copy(value, as: copied, peerNpub: peerNpub)
        } label: {
            Image(systemName: copyIndicator(copied, peerNpub: peerNpub) ? "checkmark" : systemImage)
        }
        .buttonStyle(.borderless)
    }

    private func copyIndicator(_ copied: CopyValue, peerNpub: String?) -> Bool {
        manager.copiedValue == copied && (copied != .peerNpub || manager.copiedPeerNpub == peerNpub)
    }

    private func networkNameBinding(_ network: NativeNetworkState) -> Binding<String> {
        Binding(
            get: { networkNameDrafts[network.id] ?? network.name },
            set: { networkNameDrafts[network.id] = $0 }
        )
    }

    private func networkMeshBinding(_ network: NativeNetworkState) -> Binding<String> {
        Binding(
            get: { networkMeshDrafts[network.id] ?? network.networkId },
            set: { networkMeshDrafts[network.id] = $0 }
        )
    }

    private func participantAliasBinding(_ participant: NativeParticipantState) -> Binding<String> {
        Binding(
            get: { participantAliasDrafts[participant.pubkeyHex] ?? participant.magicDnsAlias },
            set: { participantAliasDrafts[participant.pubkeyHex] = $0 }
        )
    }

    private func addParticipantToActiveNetwork() {
        guard let network = activeNetwork else {
            return
        }
        manager.addParticipant(networkId: network.id, npub: participantInput, alias: participantAliasInput)
        participantInput = ""
        participantAliasInput = ""
    }

    private func addRelay() {
        manager.addRelay(relayInput)
        relayInput = ""
    }

    private func syncDrafts() {
        guard lastSyncedRev != state.rev else {
            return
        }
        lastSyncedRev = state.rev
        nodeName = state.nodeName
        endpoint = state.endpoint
        tunnelIp = state.tunnelIp
        listenPort = String(state.listenPort)
        magicDnsSuffix = state.magicDnsSuffix
        advertisedRoutes = state.advertisedRoutes.joined(separator: ", ")

        for network in state.networks {
            networkNameDrafts[network.id] = network.name
            networkMeshDrafts[network.id] = network.networkId
            for participant in network.participants {
                participantAliasDrafts[participant.pubkeyHex] = participant.magicDnsAlias
            }
        }
    }

    private func displayName(_ network: NativeNetworkState) -> String {
        network.name.isEmpty ? "Network" : network.name
    }

    private var heroBadgeText: String {
        if state.meshReady {
            return "Mesh ready"
        }
        if state.sessionActive {
            return "Connecting"
        }
        return "VPN off"
    }

    private var heroSubtext: String {
        if state.sessionActive {
            return state.sessionStatus
        }
        if state.serviceSupported && (!state.serviceInstalled || state.serviceDisabled) {
            return "Background service needs attention"
        }
        return state.sessionStatus
    }

    private var selectedExitText: String {
        guard !state.exitNode.isEmpty else {
            return "Direct"
        }
        return short(state.exitNode, prefix: 10, suffix: 8)
    }

    private var serviceInstallButtonTitle: String {
        if manager.serviceRepairRecommended {
            return "Repair Service"
        }
        return state.serviceInstalled ? "Reinstall Service" : "Install Service"
    }

    private var shouldShowVpnDisclosure: Bool {
        state.mobile || state.vpnSessionControlSupported
    }

    private func adminSummary(_ network: NativeNetworkState) -> String {
        if network.adminNpubs.isEmpty {
            return "No admins"
        }
        return "\(network.adminNpubs.count) admin\(network.adminNpubs.count == 1 ? "" : "s")"
    }

    private func participantDetail(_ participant: NativeParticipantState) -> String {
        var parts = [
            participant.magicDnsName.isEmpty ? participant.magicDnsAlias : participant.magicDnsName,
            participant.statusText,
            participant.lastSignalText,
            participant.tunnelIp,
            "\(formatBytes(participant.rxBytes)) down / \(formatBytes(participant.txBytes)) up",
        ].filter { !$0.isEmpty }
        if !participant.advertisedRoutes.isEmpty {
            parts.append("routes \(participant.advertisedRoutes.joined(separator: ", "))")
        }
        return parts.joined(separator: " - ")
    }

    private func exitNodeCandidates(_ network: NativeNetworkState) -> [NativeParticipantState] {
        let needle = exitNodeSearch.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return network.participants.filter { participant in
            if participant.npub == state.ownNpub {
                return false
            }
            guard !needle.isEmpty else {
                return true
            }
            return [
                participant.alias,
                participant.magicDnsAlias,
                participant.magicDnsName,
                participant.npub,
                participant.tunnelIp,
            ].contains { $0.lowercased().contains(needle) }
        }
    }

    private func transportBadgeText(_ participant: NativeParticipantState) -> String {
        switch participant.state {
        case "local":
            return "Local"
        case "online":
            return "Online"
        case "pending":
            return "Pending"
        case "offline":
            return "Offline"
        default:
            return "Unknown"
        }
    }

    private func presenceBadgeText(_ participant: NativeParticipantState) -> String {
        switch participant.presenceState {
        case "local":
            return "Self"
        case "present":
            return "Present"
        case "absent":
            return "Absent"
        default:
            return "Nostr ?"
        }
    }

    private func badgeStyle(for state: String) -> BadgeStyle {
        switch state {
        case "local", "online", "present":
            return .ok
        case "pending":
            return .warn
        case "offline", "absent":
            return .bad
        default:
            return .muted
        }
    }

    private func healthStyle(_ severity: String) -> BadgeStyle {
        switch severity {
        case "critical":
            return .bad
        case "warning":
            return .warn
        case "info":
            return .muted
        default:
            return .muted
        }
    }
}

struct InviteQRCodeView: View {
    let invite: String

    var body: some View {
        if invite.isEmpty {
            RoundedRectangle(cornerRadius: 8)
                .fill(Color(nsColor: .textBackgroundColor))
                .overlay(Image(systemName: "qrcode").foregroundStyle(.secondary))
        } else if let image = qrImage(invite) {
            Image(nsImage: image)
                .interpolation(.none)
                .resizable()
                .scaledToFit()
                .padding(8)
                .background(Color.white, in: RoundedRectangle(cornerRadius: 8))
        } else {
            RoundedRectangle(cornerRadius: 8)
                .fill(Color(nsColor: .textBackgroundColor))
                .overlay(Image(systemName: "exclamationmark.triangle").foregroundStyle(.orange))
        }
    }

    private func qrImage(_ text: String) -> NSImage? {
        let data = Data(text.utf8)
        guard let filter = CIFilter(name: "CIQRCodeGenerator") else {
            return nil
        }
        filter.setValue(data, forKey: "inputMessage")
        filter.setValue("M", forKey: "inputCorrectionLevel")
        guard let output = filter.outputImage else {
            return nil
        }
        let transformed = output.transformed(by: CGAffineTransform(scaleX: 8, y: 8))
        let representation = NSCIImageRep(ciImage: transformed)
        let image = NSImage(size: representation.size)
        image.addRepresentation(representation)
        return image
    }
}

enum SidebarItem: Hashable {
    case overview
    case devices
    case sharing
    case routing
    case networks
    case deviceSettings
    case service
    case updates
    case cli
    case relays
    case diagnostics
}

enum BadgeStyle {
    case ok
    case warn
    case bad
    case muted

    var foreground: Color {
        switch self {
        case .ok:
            return .green
        case .warn:
            return .orange
        case .bad:
            return .red
        case .muted:
            return .secondary
        }
    }

    var background: Color {
        switch self {
        case .ok:
            return .green.opacity(0.14)
        case .warn:
            return .orange.opacity(0.14)
        case .bad:
            return .red.opacity(0.14)
        case .muted:
            return .secondary.opacity(0.12)
        }
    }
}

private func formatBytes(_ value: UInt64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB"]
    var amount = Double(value)
    var index = 0
    while amount >= 1024, index < units.count - 1 {
        amount /= 1024
        index += 1
    }
    if index == 0 {
        return "\(Int(amount)) \(units[index])"
    }
    return String(format: "%.1f %@", amount, units[index])
}

private func formatSeconds(_ seconds: UInt64) -> String {
    "\(seconds / 60):\(String(format: "%02d", seconds % 60))"
}

private func short(_ value: String, prefix: Int, suffix: Int) -> String {
    guard value.count > prefix + suffix + 3 else {
        return value
    }
    return "\(value.prefix(prefix))...\(value.suffix(suffix))"
}

private func firstNonEmpty(_ values: String..., fallback: String) -> String {
    values.first { !$0.isEmpty } ?? fallback
}
