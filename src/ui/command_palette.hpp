#pragma once

#include <functional>
#include <string>

namespace slop::ui::palette {

// one palette entry, built ins are generated automatically, register
// to add more
struct Command {
    std::string id;        // stable unique id
    std::string title;     // primary label, fuzzy-matched + highlighted
    std::string group;     // dim right-side tag, also searchable (e.g. "View")
    std::string shortcut;  // optional display hint, e.g. "Ctrl+1"
    std::function<void()> run;
};

// Add a persistent command. Replaces any existing command with the same id
void Register(Command c);

void Open();
void Close();
void Toggle();
bool IsOpen();

// Draw the palette overlay + handle its global open shortcut (Ctrl+Shift+P)
// Call once per frame, last, so it layers above everything else
void Render();

} // namespace slop::ui::palette
