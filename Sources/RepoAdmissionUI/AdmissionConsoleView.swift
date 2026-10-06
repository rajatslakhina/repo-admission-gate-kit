#if canImport(SwiftUI)
import SwiftUI
import RepoAdmission

/// An interactive console over the red-team fixture: what an agent's commands
/// would be allowed to do, and how sanitizing, approving and an upstream edit
/// change that.
public struct AdmissionConsoleView: View {
    @State private var model: AdmissionConsoleModel

    public init(policy: AdmissionPolicy) {
        _model = State(initialValue: AdmissionConsoleModel(policy: policy))
    }

    public init(model: AdmissionConsoleModel) {
        _model = State(initialValue: model)
    }

    public var body: some View {
        NavigationStack {
            List {
                Section { StatusHeader(model: model) }
                Section("Act on the repository") { ActionButtons(model: model) }
                Section {
                    if model.results.isEmpty {
                        Text("No probes yet.").foregroundStyle(.secondary)
                    }
                    ForEach(model.results) { ProbeRow(result: $0) }
                } header: {
                    Text("What the agent may run")
                } footer: {
                    Text("Each command is classified into the triggers it fires, and only vectors those triggers reach are checked.")
                }
                if model.groups.isEmpty {
                    Section("Execution vectors") {
                        Text("No execution vectors found.").foregroundStyle(.secondary)
                    }
                }
                ForEach(model.groups) { group in
                    Section("\(group.family.rawValue) · \(group.findings.count)") {
                        ForEach(group.findings, id: \.vector.id) { FindingRow(finding: $0) }
                    }
                }
                Section {
                    if model.logTail.isEmpty {
                        Text("Nothing recorded yet.").foregroundStyle(.secondary)
                    }
                    ForEach(model.logTail, id: \.sequence) { entry in
                        VStack(alignment: .leading, spacing: 2) {
                            Text("#\(entry.sequence) · \(entry.hash.short)").font(.caption.monospaced())
                            Text(Self.summary(entry.event)).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                } header: {
                    Text("Provenance log (newest first)")
                } footer: {
                    Text(Self.chainText(model.chainStatus))
                }
            }
            .navigationTitle("Repo Admission")
            .task { await model.refresh() }
        }
    }

    static func summary(_ event: ProvenanceEvent) -> String {
        switch event {
        case let .assessed(_, _, surface, blocking, pending): "assessed — \(blocking) denied, \(pending) pending, surface \(surface.short)"
        case let .approved(_, surface, approver): "approved \(surface.short) by \(approver)"
        case let .approvalVoided(_, approved, current): "approval \(approved.short) voided — surface is now \(current.short)"
        case .revoked: "approval revoked"
        case let .sanitized(_, actions, remaining): "sanitized \(actions) change(s), \(remaining) remain"
        case let .decided(command, verdict, _): "\(verdict.rawValue.uppercased()) \(command)"
        }
    }

    static func chainText(_ status: ProvenanceLog.Verification) -> String {
        switch status {
        case .intact(let entries): "Hash chain verified across \(entries) retained entries."
        case let .broken(sequence, reason): "Hash chain BROKEN at #\(sequence): \(reason)"
        }
    }
}

private struct StatusHeader: View {
    let model: AdmissionConsoleModel

    var body: some View {
        let counts = model.counts
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Image(systemName: headline.icon).foregroundStyle(headline.color)
                Text(headline.text).font(.headline)
            }
            HStack(spacing: 12) {
                CountChip(value: counts.blocking, label: "denied", color: .red)
                CountChip(value: counts.pending, label: "need approval", color: .orange)
                CountChip(value: counts.allowed, label: "allowed", color: .green)
            }
            if let surface = model.surface {
                Text("Approval surface \(surface.short)").font(.caption.monospaced()).foregroundStyle(.secondary)
            }
            Text(model.lastEvent).font(.footnote)
        }
        .padding(.vertical, 4)
    }

    private var headline: (text: String, icon: String, color: Color) {
        let counts = model.counts
        if counts.blocking > 0 { return ("Quarantined — denied vectors present", "xmark.shield.fill", .red) }
        if model.isApprovalCurrent { return ("Admitted — approval matches the current surface", "checkmark.shield.fill", .green) }
        if model.approved != nil { return ("Re-quarantined — the surface changed after approval", "exclamationmark.shield.fill", .orange) }
        if counts.pending > 0 { return ("Awaiting approval", "shield.lefthalf.filled", .orange) }
        return ("Admitted — nothing needs approval", "checkmark.shield.fill", .green)
    }
}

private struct CountChip: View {
    let value: Int
    let label: String
    let color: Color

    var body: some View {
        VStack(spacing: 0) {
            Text("\(value)").font(.title3.bold()).foregroundStyle(color)
            Text(label).font(.caption2).foregroundStyle(.secondary)
        }
    }
}

private struct ActionButtons: View {
    let model: AdmissionConsoleModel

    var body: some View {
        Button("Sanitize .git/ (never touches tracked files)") { Task { await model.sanitize() } }
        Button("Approve current surface") { Task { await model.approve() } }
            .disabled(model.surface == nil)
        Button("Pull an upstream change to a script phase") { Task { await model.pullUpstreamChange() } }
        Button("Reset", role: .destructive) { Task { await model.reset() } }
    }
}

private struct ProbeRow: View {
    let result: ProbeResult

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .firstTextBaseline) {
                VerdictBadge(verdict: result.verdict)
                Text(result.command).font(.caption.monospaced()).lineLimit(2)
            }
            Text(result.reason).font(.caption2).foregroundStyle(.secondary).lineLimit(4)
        }
    }
}

private struct VerdictBadge: View {
    let verdict: Verdict

    var body: some View {
        Text(verdict.rawValue.uppercased())
            .font(.caption2.bold())
            .padding(.horizontal, 6).padding(.vertical, 2)
            .background(color.opacity(0.18), in: Capsule())
            .foregroundStyle(color)
    }

    private var color: Color {
        switch verdict {
        case .allow: .green
        case .ask: .orange
        case .deny: .red
        }
    }
}

private struct FindingRow: View {
    let finding: Finding

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack {
                Circle().fill(color).frame(width: 8, height: 8)
                Text(finding.vector.subject).font(.callout.monospaced()).lineLimit(1)
            }
            Text("\(finding.vector.vectorClass.rawValue) · \(finding.vector.path)").font(.caption).foregroundStyle(.secondary)
            Text(finding.reason).font(.caption2).foregroundStyle(.secondary)
        }
    }

    private var color: Color {
        switch finding.disposition {
        case .allow: .green
        case .requireApproval: .orange
        case .deny: .red
        }
    }
}
#endif
