// Near-native probe: UWP shell.
//
// All of the actual probing lives in probes.cpp (plain Win32, also built as a
// console harness). This file only gives it a window to live in, a folder to
// write to (LocalState), and two message dialogs:
//   1. after the safe tests: summary + an offer to run the crash-risk tests
//   2. after the crash-risk tests (if the process survives them)
// If a crash-risk test kills the app, relaunch it: the previous run's verdict
// is recovered from LocalState\nn-probe-state.txt.

#include <windows.h>
#include <stdio.h>
#include <string>
#include <thread>
#include <agile.h>
#include "probes.h"

using namespace Platform;
using namespace Windows::ApplicationModel::Core;
using namespace Windows::UI::Core;
using namespace Windows::UI::Popups;
using namespace Windows::Storage;

static std::string narrow(const std::wstring &w)
{
    if (w.empty())
        return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string out((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &out[0], n, nullptr, nullptr);
    return out;
}

static std::wstring widen(const std::string &s)
{
    if (s.empty())
        return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring out((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &out[0], n);
    return out;
}

static std::string DialogText(const char *header, const std::wstring &path)
{
    std::string text = header;
    text += "\n\n";
    for (const std::string &s : nn::Summary())
        text += s + "\n";
    text += "\nFull report: ";
    text += narrow(path);
    return text;
}

static std::string RunSafe(const std::wstring &dir)
{
    std::wstring path = dir + L"\\nn-probe.txt";
    FILE *f = nullptr;
    _wfopen_s(&f, path.c_str(), L"w");
    nn::SetLogFile(f);
    nn::SetStateDir(dir);
    nn::ClearSummary();
    nn::Log("Report file: %ls", path.c_str());
    nn::ResolveCrashedTests();
    nn::RunSafeProbes();
    nn::ReportDangerousState();
    if (f)
        fclose(f);
    nn::SetLogFile(nullptr);
    return DialogText("Safe tests finished.", path);
}

static std::string RunDanger(const std::wstring &dir)
{
    std::wstring path = dir + L"\\nn-probe.txt";
    FILE *f = nullptr;
    _wfopen_s(&f, path.c_str(), L"a");
    nn::SetLogFile(f);
    nn::SetStateDir(dir);
    nn::ClearSummary();
    nn::Log("");
    nn::Log("######## crash-risk tests ########");
    nn::RunDangerous();
    nn::ReportDangerousState();
    if (f)
        fclose(f);
    nn::SetLogFile(nullptr);
    return DialogText("Crash-risk tests finished (the app survived all of them).", path);
}

static void ShowFinal(Platform::Agile<CoreWindow ^> w, const std::string &text)
{
    String ^msg = ref new String(widen(text).c_str());
    w.Get()->Dispatcher->RunAsync(CoreDispatcherPriority::Normal, ref new DispatchedHandler([msg]() {
        MessageDialog ^dlg = ref new MessageDialog(msg, "Near-native probe: crash-risk tests done");
        dlg->ShowAsync();
    }));
}

static void ShowSafe(Platform::Agile<CoreWindow ^> w, const std::wstring &dir, const std::string &text)
{
    String ^msg = ref new String(widen(text).c_str());
    w.Get()->Dispatcher->RunAsync(CoreDispatcherPriority::Normal, ref new DispatchedHandler([w, dir, msg]() {
        MessageDialog ^dlg = ref new MessageDialog(msg, "Near-native probe: safe tests done");
        dlg->Commands->Append(ref new UICommand("Run crash-risk tests (app may close)", ref new UICommandInvokedHandler([w, dir](IUICommand ^) {
            std::thread([w, dir]() {
                std::string t = RunDanger(dir);
                ShowFinal(w, t);
            }).detach();
        })));
        dlg->Commands->Append(ref new UICommand("Done"));
        dlg->DefaultCommandIndex = 1;
        dlg->CancelCommandIndex = 1;
        dlg->ShowAsync();
    }));
}

namespace NnProbe
{
ref class App sealed : public IFrameworkViewSource, public IFrameworkView
{
public:
    virtual IFrameworkView ^ CreateView() { return this; }
    virtual void Initialize(CoreApplicationView ^) {}
    virtual void SetWindow(CoreWindow ^) {}
    virtual void Load(String ^) {}
    virtual void Uninitialize() {}
    virtual void Run()
    {
        CoreWindow ^window = CoreWindow::GetForCurrentThread();
        window->Activate();
        std::wstring dir = ApplicationData::Current->LocalFolder->Path->Data();
        Platform::Agile<CoreWindow ^> agileWindow(window);
        std::thread([agileWindow, dir]() {
            std::string text = RunSafe(dir);
            ShowSafe(agileWindow, dir, text);
        }).detach();
        window->Dispatcher->ProcessEvents(CoreProcessEventsOption::ProcessUntilQuit);
    }
};
} // namespace NnProbe

[Platform::MTAThread] int main(Platform::Array<Platform::String ^> ^)
{
    CoreApplication::Run(ref new NnProbe::App());
    return 0;
}
