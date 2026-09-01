#pragma once

namespace slop::ui::dockspace {

// render the workbench host, menu bar, dockspace, status bar, all open
// panels, call once per frame
void Render();

// Rebuild the default dock layout on the next Render() call
void RequestReset();

} // namespace slop::ui::dockspace
