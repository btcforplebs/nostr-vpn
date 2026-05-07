import AppKit
import SwiftUI

struct StatusMenuView: View {
    @ObservedObject var manager: AppManager
    let openMainWindow: () -> Void

    private var state: NativeAppState {
        manager.state
    }

    private var activeNetwork: NativeNetworkState? {
        manager.activeNetwork
    }

    var body: some View {
        Button("Open Nostr VPN", action: openMainWindow)
        Divider()
        Button(state.vpnEnabled ? "Turn VPN Off" : "Turn VPN On") {
            manager.toggleVpn()
        }
        .disabled(manager.actionInFlight || !state.vpnControlSupported)
        Button(state.advertiseExitNode ? "Stop Offering Exit" : "Offer Private Exit") {
            manager.setAdvertiseExitNode(!state.advertiseExitNode)
        }
        Divider()
        Button("Copy This Device") {
            manager.copy(thisDeviceCopyValue, as: .pubkey)
        }
        .disabled(thisDeviceCopyValue.isEmpty)
        if let activeNetwork {
            Menu(activeNetwork.name.isEmpty ? "Network Devices" : activeNetwork.name) {
                ForEach(activeNetwork.participants, id: \.pubkeyHex) { participant in
                    Button(participantMenuTitle(participant)) {
                        manager.copy(participant.npub, as: .peerNpub, peerNpub: participant.npub)
                    }
                }
            }
            Menu("Exit Node") {
                Button("No exit node") {
                    manager.setExitNode("")
                }
                ForEach(activeNetwork.participants.filter { $0.offersExitNode }, id: \.pubkeyHex) { participant in
                    Button(participant.magicDnsName.isEmpty ? participant.alias : participant.magicDnsName) {
                        manager.setExitNode(participant.npub)
                    }
                }
            }
        }
        Divider()
        Button("Refresh") {
            manager.refresh()
        }
        Button("Quit") {
            NSApp.terminate(nil)
        }
    }

    private var thisDeviceCopyValue: String {
        if !state.ownNpub.isEmpty {
            return state.ownNpub
        }
        return state.tunnelIp
    }

    private func participantMenuTitle(_ participant: NativeParticipantState) -> String {
        let name = participant.magicDnsName.isEmpty ? participant.alias : participant.magicDnsName
        if participant.tunnelIp.isEmpty || participant.tunnelIp == "-" {
            return name
        }
        return "\(name) (\(participant.tunnelIp))"
    }
}
