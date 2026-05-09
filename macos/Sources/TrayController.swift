import AppKit
import Combine
import SwiftUI

/// AppKit-backed tray menu.
///
/// SwiftUI's `MenuBarExtra` rebuilt the menu hierarchy on every AppManager
/// state publish (~1.5s tick), which dismissed any submenu the user had
/// open. NSMenuItems are persistent AppKit objects: mutating their titles
/// in place leaves an open submenu undisturbed.
///
/// Menu layout:
///
///     ☐ VPN                       ← toggle, first item
///     ─────────────
///     <device-name>               ← disabled section header
///     Copy Device ID
///     ─────────────
///     <network-name> ▶            ← list of network peers (copy npub)
///     Exit Node ▶                 ← offer toggle + selection
///       <exit status, if any>
///       ☐ Offer This Device
///       ─────────
///       ☑ No exit node
///       Device 1
///       Device 2
///     ─────────────
///     Open Nostr VPN
///     Quit
@MainActor
final class TrayController: NSObject {
    private let manager: AppManager
    private let openMainWindow: () -> Void

    private let statusItem: NSStatusItem
    private let menu = NSMenu()

    // Stable items
    private let vpnToggleItem = NSMenuItem()
    private let deviceNameItem = NSMenuItem()
    private let copyDeviceIdItem = NSMenuItem()
    private let networkSubmenuItem = NSMenuItem()
    private let exitNodeSubmenuItem = NSMenuItem()
    private let openItem = NSMenuItem()
    private let quitItem = NSMenuItem()

    private let networkSubmenu = NSMenu()
    private let exitNodeSubmenu = NSMenu()

    // Stable items inside Exit Node submenu
    private let exitNodeStatusItem = NSMenuItem()
    private let offerExitItem = NSMenuItem()
    private let exitNodeSelectionSeparator = NSMenuItem.separator()
    private let noExitNodeItem = NSMenuItem()

    private var cancellables = Set<AnyCancellable>()
    private var lastSnapshot: MenuSnapshot?

    init(manager: AppManager, openMainWindow: @escaping () -> Void) {
        self.manager = manager
        self.openMainWindow = openMainWindow
        self.statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        super.init()

        configureStatusItem()
        buildMenuSkeleton()
        statusItem.menu = menu

        refreshFromState()
        manager.objectWillChange
            .receive(on: RunLoop.main)
            .sink { [weak self] _ in
                Task { @MainActor [weak self] in
                    self?.refreshFromState()
                }
            }
            .store(in: &cancellables)
    }

    // MARK: - Setup

    private func configureStatusItem() {
        guard let button = statusItem.button else { return }
        if let image = NSImage(named: "TrayIcon") {
            image.isTemplate = true
            button.image = image
        }
        button.toolTip = "Nostr VPN"
    }

    private func buildMenuSkeleton() {
        vpnToggleItem.title = "VPN"
        vpnToggleItem.target = self
        vpnToggleItem.action = #selector(handleToggleVpn)

        deviceNameItem.isEnabled = false

        copyDeviceIdItem.title = "Copy Device ID"
        copyDeviceIdItem.target = self
        copyDeviceIdItem.action = #selector(handleCopyDeviceId)

        networkSubmenuItem.submenu = networkSubmenu
        networkSubmenuItem.isHidden = true

        exitNodeSubmenuItem.title = "Exit Node"
        exitNodeSubmenuItem.submenu = exitNodeSubmenu

        // Exit Node submenu skeleton.
        exitNodeStatusItem.isEnabled = false
        exitNodeStatusItem.isHidden = true

        offerExitItem.title = "Offer This Device"
        offerExitItem.target = self
        offerExitItem.action = #selector(handleToggleOfferExit)

        noExitNodeItem.title = "No exit node"
        noExitNodeItem.target = self
        noExitNodeItem.action = #selector(handleSelectNoExit)

        exitNodeSubmenu.addItem(exitNodeStatusItem)
        exitNodeSubmenu.addItem(offerExitItem)
        exitNodeSubmenu.addItem(exitNodeSelectionSeparator)
        exitNodeSubmenu.addItem(noExitNodeItem)
        // Peer items appended in updateExitNodeSubmenu().

        openItem.title = "Open Nostr VPN"
        openItem.target = self
        openItem.action = #selector(handleOpenMain)

        quitItem.title = "Quit"
        quitItem.target = self
        quitItem.action = #selector(handleQuit)
        quitItem.keyEquivalent = "q"

        menu.addItem(vpnToggleItem)
        menu.addItem(.separator())
        menu.addItem(deviceNameItem)
        menu.addItem(copyDeviceIdItem)
        menu.addItem(.separator())
        menu.addItem(networkSubmenuItem)
        menu.addItem(exitNodeSubmenuItem)
        menu.addItem(.separator())
        menu.addItem(openItem)
        menu.addItem(quitItem)
    }

    // MARK: - Update from state

    private func refreshFromState() {
        let snapshot = MenuSnapshot.capture(from: manager)
        if snapshot == lastSnapshot {
            return
        }
        lastSnapshot = snapshot

        // VPN toggle
        vpnToggleItem.state = snapshot.vpnEnabled ? .on : .off
        vpnToggleItem.isEnabled = snapshot.vpnTogglable

        // Device name + copy
        deviceNameItem.title = snapshot.deviceName
        copyDeviceIdItem.isEnabled = !snapshot.deviceIdValue.isEmpty

        // Network submenu
        networkSubmenuItem.title = snapshot.networkTitle ?? "Network Devices"
        networkSubmenuItem.isHidden = snapshot.networkTitle == nil
        rebuildSubmenu(networkSubmenu, items: snapshot.networkItems) { [weak self] item in
            self?.manager.copy(item.npub, as: .peerNpub, peerNpub: item.npub)
        }

        // Exit Node submenu
        exitNodeStatusItem.title = snapshot.exitNodeStatusText
        exitNodeStatusItem.isHidden = snapshot.exitNodeStatusText.isEmpty
        offerExitItem.state = snapshot.advertiseExitNode ? .on : .off
        noExitNodeItem.state = snapshot.exitNodeNpub.isEmpty ? .on : .off
        rebuildExitNodePeers(items: snapshot.exitNodeItems, selectedNpub: snapshot.exitNodeNpub)

        statusItem.button?.toolTip = snapshot.tooltip
    }

    private func rebuildSubmenu<T: Equatable>(
        _ submenu: NSMenu,
        items: [SubmenuItem<T>],
        action: @escaping (SubmenuItem<T>) -> Void
    ) {
        let current: [SubmenuItem<T>] = submenu.items.compactMap { item in
            (item.representedObject as? SubmenuClickPayload<T>)?.item
        }
        if current == items {
            return
        }
        submenu.removeAllItems()
        for item in items {
            let menuItem = NSMenuItem(
                title: item.title, action: #selector(handleSubmenuClick(_:)), keyEquivalent: "")
            menuItem.target = self
            menuItem.representedObject = SubmenuClickPayload(item: item, action: action)
            submenu.addItem(menuItem)
        }
    }

    /// The Exit Node submenu has stable header items (status, offer, separator,
    /// "No exit node") followed by a dynamic list of peers offering exit. Keep
    /// the header items in place and rebuild the trailing peer list.
    private func rebuildExitNodePeers(items: [SubmenuItem<ExitNodeRow>], selectedNpub: String) {
        // Drop everything past the "No exit node" item.
        let keepCount = exitNodeSubmenu.items.firstIndex(of: noExitNodeItem).map { $0 + 1 } ?? 0
        while exitNodeSubmenu.items.count > keepCount {
            exitNodeSubmenu.removeItem(at: exitNodeSubmenu.items.count - 1)
        }
        for item in items {
            let menuItem = NSMenuItem(
                title: item.title,
                action: #selector(handleSelectExitNode(_:)),
                keyEquivalent: "")
            menuItem.target = self
            menuItem.representedObject = item.npub
            menuItem.state = item.npub == selectedNpub ? .on : .off
            exitNodeSubmenu.addItem(menuItem)
        }
    }

    // MARK: - Action handlers

    @objc private func handleToggleVpn() {
        manager.toggleVpn()
    }

    @objc private func handleToggleOfferExit() {
        manager.setAdvertiseExitNode(!manager.state.advertiseExitNode)
    }

    @objc private func handleCopyDeviceId() {
        let value = manager.state.ownNpub
        guard !value.isEmpty else { return }
        manager.copy(value, as: .pubkey)
    }

    @objc private func handleSubmenuClick(_ sender: NSMenuItem) {
        guard let payload = sender.representedObject as? AnySubmenuClickPayload else { return }
        payload.invoke()
    }

    @objc private func handleSelectNoExit() {
        manager.setExitNode("")
    }

    @objc private func handleSelectExitNode(_ sender: NSMenuItem) {
        guard let npub = sender.representedObject as? String else { return }
        manager.setExitNode(npub)
    }

    @objc private func handleOpenMain() {
        openMainWindow()
    }

    @objc private func handleQuit() {
        NSApp.terminate(nil)
    }
}

// MARK: - Menu snapshot

private struct MenuSnapshot: Equatable {
    let vpnEnabled: Bool
    let vpnTogglable: Bool
    let deviceName: String
    let deviceIdValue: String
    let networkTitle: String?
    let networkItems: [SubmenuItem<NetworkRow>]
    let exitNodeStatusText: String
    let advertiseExitNode: Bool
    let exitNodeNpub: String
    let exitNodeItems: [SubmenuItem<ExitNodeRow>]
    let tooltip: String

    @MainActor
    static func capture(from manager: AppManager) -> MenuSnapshot {
        let state = manager.state
        let activeNetwork = manager.activeNetwork

        var networkTitle: String? = nil
        var networkItems: [SubmenuItem<NetworkRow>] = []
        var exitNodeItems: [SubmenuItem<ExitNodeRow>] = []

        if let activeNetwork {
            networkTitle = activeNetwork.name.isEmpty ? "Network Devices" : activeNetwork.name
            networkItems = activeNetwork.participants.map { p in
                SubmenuItem<NetworkRow>(
                    title: participantMenuTitle(p),
                    npub: p.npub,
                    payload: NetworkRow(pubkeyHex: p.pubkeyHex)
                )
            }
            exitNodeItems = activeNetwork.participants.filter { $0.offersExitNode }
                .map { p in
                    SubmenuItem<ExitNodeRow>(
                        title: p.magicDnsName.isEmpty ? p.alias : p.magicDnsName,
                        npub: p.npub,
                        payload: ExitNodeRow(pubkeyHex: p.pubkeyHex)
                    )
                }
        }

        let tooltip: String = {
            if !state.exitNodeStatusText.isEmpty { return state.exitNodeStatusText }
            if !state.vpnStatus.isEmpty { return state.vpnStatus }
            return "Nostr VPN"
        }()

        return MenuSnapshot(
            vpnEnabled: state.vpnEnabled,
            vpnTogglable: !manager.actionInFlight && state.vpnControlSupported,
            deviceName: resolveDeviceName(from: state),
            deviceIdValue: state.ownNpub,
            networkTitle: networkTitle,
            networkItems: networkItems,
            exitNodeStatusText: state.exitNodeStatusText,
            advertiseExitNode: state.advertiseExitNode,
            exitNodeNpub: state.exitNode,
            exitNodeItems: exitNodeItems,
            tooltip: tooltip
        )
    }
}

private func resolveDeviceName(from state: NativeAppState) -> String {
    if !state.selfMagicDnsName.isEmpty {
        return state.selfMagicDnsName
    }
    if !state.nodeName.isEmpty {
        return state.nodeName
    }
    if !state.tunnelIp.isEmpty, state.tunnelIp != "-" {
        return state.tunnelIp
    }
    return "This Device"
}

private func participantMenuTitle(_ participant: NativeParticipantState) -> String {
    let name = participant.magicDnsName.isEmpty ? participant.alias : participant.magicDnsName
    if participant.tunnelIp.isEmpty || participant.tunnelIp == "-" {
        return name
    }
    return "\(name) (\(participant.tunnelIp))"
}

private struct NetworkRow: Equatable { let pubkeyHex: String }
private struct ExitNodeRow: Equatable { let pubkeyHex: String }

private struct SubmenuItem<Payload: Equatable>: Equatable {
    let title: String
    let npub: String
    let payload: Payload
}

private protocol AnySubmenuClickPayload {
    func invoke()
}

private struct SubmenuClickPayload<T: Equatable>: AnySubmenuClickPayload {
    let item: SubmenuItem<T>
    let action: (SubmenuItem<T>) -> Void
    func invoke() { action(item) }
}
