// SPDX-License-Identifier: AGPL-3.0-only
/// An empty host app. XCUITest bundles need a host target; the tests drive Safari, never this app.
import SwiftUI

/// The host app: one window with one line of text.
@main struct QAHost: App {
    /// The single scene.
    var body: some Scene { WindowGroup { Text("infraternal device QA runner") } }
}
