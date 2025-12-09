#include <winsock2.h>
#include <windows.h>
#include <detours/detours.h>
#include <string>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

template<class t = uint32_t>
inline t ReadMemory(uint32_t addr) {
    return *(t*)addr;
}
template<class t = uint32_t>
inline void WriteMemory(uint32_t addr, t value) {
    *(t*)addr = value;
}

// copied from GHost++ util.cpp
std::vector<uint8_t> EncodeGameDesc(std::vector<uint8_t>& data) {
    unsigned char Mask = 1;
    std::vector<uint8_t> Result;

    for (unsigned int i = 0; i < data.size(); ++i) {
        if ((data[i] % 2) == 0)
            Result.push_back(data[i] + 1);
        else {
            Result.push_back(data[i]);
            Mask |= 1 << ((i % 7) + 1);
        }

        if (i % 7 == 6 || i == data.size() - 1) {
            Result.insert(Result.end() - 1 - (i % 7), Mask);
            Mask = 1;
        }
    }

    return Result;
}

#pragma region storm
void(__stdcall* SRegLoadString)(const char*, const char*, uint32_t, char*, uint32_t);
void(__stdcall* SMemFree)(void*, const char*, uint32_t, uint32_t);
#pragma endregion

#pragma region war3
uint32_t base;

#define PROP_NET                            0xE
#define MAP_FOG_DEFAULT                     0x8
#define MAP_TEAMS_TOGETHER                  0x40
#define MAP_RESOURCE_TRADING_ALLIES_ONLY    0x200
#define MAP_LOCK_ALLIANCE_CHANGES           0x400
#define DEFAULT_MAP_FLAG                    (MAP_LOCK_ALLIANCE_CHANGES | MAP_RESOURCE_TRADING_ALLIES_ONLY | MAP_TEAMS_TOGETHER | MAP_FOG_DEFAULT)

struct GAMEDATA {
    char name[32];
    char password[16];
    char desc[128];
    uint32_t max_players;
    uint32_t category_id;
}; static_assert(sizeof(GAMEDATA) == 184);
struct CGlueMgr {
    uint32_t unk_0[97];
    uint32_t menu;
    uint32_t unk_392[9];
}; static_assert(sizeof(CGlueMgr) == 428);
struct NetProvider {
    uint32_t unk_0[9];
    uint32_t program;
    uint32_t version;
    uint32_t unk_44[379];
    uint32_t max_game;
    uint32_t unk_1564[9];
}; static_assert(sizeof(NetProvider) == 1600);
struct CGameChatroom {
    uint32_t unk_0[90];
    uint32_t session;
    uint32_t unk_1564[45];
}; static_assert(sizeof(CGameChatroom) == 544);
struct CNetGlueGameSetup {
    struct CEventDistFilesOutstanding {
        uint32_t unk_0[4];
        uint32_t count;
    }; static_assert(sizeof(CEventDistFilesOutstanding) == 20);
};
template <class T>
struct TSGrowableArray {
    uint32_t allocated_size;
    uint32_t size;
    T* data;
    uint32_t unk_12;

    ~TSGrowableArray() {
        if (data)
            SMemFree(data, __FILE__, __LINE__, 0);
    }
}; static_assert(sizeof(TSGrowableArray<void>) == 16);

uint32_t(__fastcall* PropGet)(uint32_t);

CGlueMgr* (__cdecl* CGlueMgr_Get)();
void(__fastcall* CGlueMgr_SetGlueScreen)(uint32_t, uint32_t);

void(__thiscall* CGameChatroom_OnDistFilesOutstanding)(CGameChatroom*, uint32_t);
void(__thiscall* CGameChatroom_OnPlayerJoin)(CGameChatroom*, uint32_t);

BOOL(__fastcall* WorldOpenMapArchive)(const char*);
BOOL(__fastcall* WorldGetMapInfo)(const char*, void*, TSGrowableArray<void>* players, void*, void*);

void(__fastcall* NetInitializeProvider)(uint32_t, uint32_t);
void(__fastcall* NetRegisterEvent)(uint32_t, uint32_t, uint32_t, uint32_t); 
void(__fastcall* NetGlueGameCreate)(const char*, const char*, const char*, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, const char*, BOOL, BOOL, BOOL, uint32_t);
void(__thiscall* NetGlueGameJoin)(uint32_t, const char*, const char*, uint32_t); 
void(__fastcall* NetStartGame)(uint32_t);
void(__fastcall* NetLeaveGame)(uint32_t, uint32_t, uint32_t);

uint32_t(__thiscall* Net_NetProvider_RemoteAdAdd)(NetProvider*, sockaddr_in*, sockaddr_in*, uint32_t, uint32_t, uint32_t, uint32_t, GAMEDATA*, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);

uint32_t(__fastcall* Net_RandomNumber)(uint32_t);

BOOL(__thiscall* CGameWar3_LoadMapSetup)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
#pragma endregion

HANDLE hEvent[] = {
    NULL,
    NULL
};
char player_name[16];
std::string w2a(const std::wstring_view& str) {
    std::string result;
    if (str.empty())
        return result;

    const int wlen = WideCharToMultiByte(CP_ACP, 0, str.data(), static_cast<int>(str.size()), NULL, 0, 0 , NULL);
    if (wlen <= 0)
        return result;

    result.resize(wlen);
    WideCharToMultiByte(CP_ACP, 0, str.data(), static_cast<int>(str.size()), result.data(), static_cast<int>(result.size()), 0, NULL);
    return result;
}

#pragma region host
std::string filepath;
int player_count;
int player_joined = 1;
bool leave_is_error = false;
void(__fastcall* real_CGlueMgr_SetGlueScreen)(uint32_t, uint32_t);
void __fastcall fake_CGlueMgr_SetGlueScreen_host(uint32_t a1, uint32_t a2) {
    // main menu
    if (a1 == 2 && !filepath.empty()) {
        // initialize NetProvider
        NetInitializeProvider('TCPN', 0);

        // set to create game menu
        real_CGlueMgr_SetGlueScreen(9, 1);

        // open map
        if (!WorldOpenMapArchive(filepath.c_str())) {
            SetEvent(hEvent[1]);
            MessageBoxA(NULL, "Load map failed", "ERROR", MB_OK);
            TerminateProcess(GetCurrentProcess(), 1);
        }

        // get map info
        TSGrowableArray<void> players{};
        if (!WorldGetMapInfo(filepath.c_str(), NULL, &players, NULL, NULL)) {
            SetEvent(hEvent[1]);
            MessageBoxA(NULL, "Load map info failed", "ERROR", MB_OK);
            TerminateProcess(GetCurrentProcess(), 1);
        }

        // create game
        NetGlueGameCreate(
            "quicktest",
            "quicktest",
            filepath.c_str(),
            players.size,
            players.size,
            1, // game type
            2, // game speed
            DEFAULT_MAP_FLAG,
            player_name,
            false,
            false,
            false,
            0
        );

        // menu ui
        auto glue_mgr = CGlueMgr_Get();
        NetRegisterEvent(0x40090073, 6, glue_mgr->menu, 0);
        NetRegisterEvent(0x40090073, 6, glue_mgr->menu, 1);

        filepath.clear();
        leave_is_error = true;

        return;
    }
    return real_CGlueMgr_SetGlueScreen(a1, a2);
}
void(__thiscall* real_CGameChatroom_OnDistFilesOutstanding)(CGameChatroom*, CNetGlueGameSetup::CEventDistFilesOutstanding*);
void __fastcall fake_CGameChatroom_OnDistFilesOutstanding(CGameChatroom* _this, uint32_t, CNetGlueGameSetup::CEventDistFilesOutstanding* e) {
    real_CGameChatroom_OnDistFilesOutstanding(_this, e);
    // all ready
    if (e->count == 1 && player_joined == 1)
        SetEvent(hEvent[0]);
    if (e->count == 0 && player_count == player_joined) {
        // start game
        NetStartGame(_this->session);
        // cleanup
        CloseHandle(hEvent[0]);
        CloseHandle(hEvent[1]);
        hEvent[0] = NULL;
        hEvent[1] = NULL;
        leave_is_error = false;
    }
}
void(__thiscall* real_CGameChatroom_OnPlayerJoin)(uint32_t, uint32_t);
void __fastcall fake_CGameChatroom_OnPlayerJoin(uint32_t a1, uint32_t, uint32_t a2) {
    real_CGameChatroom_OnPlayerJoin(a1, a2);
    player_joined++;
}
uint32_t(__fastcall* real_Net_RandomNumber)(uint32_t);
uint32_t __fastcall fake_Net_RandomNumber(uint32_t) {
    return 'test';
}
uint32_t(__fastcall* real_CGameWar3_LoadMapSetup)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
uint32_t __fastcall fake_CGameWar3_LoadMapSetup(uint32_t a1, uint32_t, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5) {
    auto ret = real_CGameWar3_LoadMapSetup(a1, a2, a3, a4, a5);
    if (!ret) {
        SetEvent(hEvent[1]);
        MessageBoxA(NULL, "Load map setup failed", "ERROR", MB_OK);
        TerminateProcess(GetCurrentProcess(), 1);
    }
    MessageBoxA(NULL, "Load map setup failed", "ERROR", MB_OK);
    // host ready to accept join request
    SetEvent(hEvent[0]);

    return ret;
}
void(__fastcall* real_NetLeaveGame)(uint32_t, uint32_t, uint32_t);
void __fastcall fake_NetLeaveGame(uint32_t a1, uint32_t a2, uint32_t a3) {
    if (leave_is_error) {
        SetEvent(hEvent[1]);
        MessageBoxA(NULL, "Unknown error (host left game)", "ERROR", MB_OK);
        TerminateProcess(GetCurrentProcess(), 1);
    }
    return real_NetLeaveGame(a1, a2, a3);
}
long(__stdcall* real_SEH_handler)(EXCEPTION_POINTERS* ExceptionInfo) = 0;
long WINAPI fake_SEH_handler(EXCEPTION_POINTERS* ExceptionInfo) {
    if (hEvent[1]) {
        SetEvent(hEvent[1]);
        MessageBoxA(NULL, "Unknown error", "ERROR", MB_OK);
    }
    return real_SEH_handler(ExceptionInfo);
}
#pragma endregion

#pragma region join
void __fastcall fake_CGlueMgr_SetGlueScreen_join(uint32_t a1, uint32_t a2) {
    // main menu
    if (a1 == 2 && hEvent[0]) {
        // cleanup
        CloseHandle(hEvent[0]);
        CloseHandle(hEvent[1]);
        hEvent[0] = NULL;
        hEvent[1] = NULL;

        // initialize NetProvider
        NetInitializeProvider('TCPN', 0);

        // set to LAN menu
        real_CGlueMgr_SetGlueScreen(8, 1);

        // construct local server address
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.S_un.S_addr = 0x0100007F; // 127.0.0.1
        addr.sin_port = 0xE017; // 6112

        // construct raw game data;
        std::vector<uint8_t> raw_game_data;

        // game speed
        raw_game_data.push_back(2);
        // map flag
        raw_game_data.push_back((DEFAULT_MAP_FLAG >> 0) & 0xFF);
        raw_game_data.push_back((DEFAULT_MAP_FLAG >> 8) & 0xFF);
        raw_game_data.push_back((DEFAULT_MAP_FLAG >> 16) & 0xFF);
        raw_game_data.push_back((DEFAULT_MAP_FLAG >> 24) & 0xFF);

        // map width (not important)
        raw_game_data.push_back(0x00);
        raw_game_data.push_back(0x00);

        // map height (not important)
        raw_game_data.push_back(0x00);
        raw_game_data.push_back(0x00);

        // CRC (disable CRC check)
        raw_game_data.push_back(0xFF);
        raw_game_data.push_back(0xFF);
        raw_game_data.push_back(0xFF);
        raw_game_data.push_back(0xFF);

        // file path (not important)
        raw_game_data.insert(raw_game_data.end(), (uint8_t*)"quicktest", (uint8_t*)"quicktest" + sizeof("quicktest"));

        // host name (not important)
        raw_game_data.insert(raw_game_data.end(), (uint8_t*)"quicktest", (uint8_t*)"quicktest" + sizeof("quicktest"));

        // ???
        raw_game_data.push_back(0);

        // encode
        std::vector<uint8_t> game_desc = EncodeGameDesc(raw_game_data);

        // construct game data
        GAMEDATA game_data{};
        // game name (not important)
        strcpy_s(game_data.name, "quicktest");
        // encoded game data
        strncpy_s(game_data.desc, (char*)&game_desc[0], game_desc.size());

        // max player (not important)
        game_data.max_players = 12;
        // ???
        game_data.category_id = 0;

        // get net provider
        auto net = (NetProvider*)PropGet(PROP_NET);

        // set max game (default 0)
        net->max_game = 1;

        // add game and send join request
        NetGlueGameJoin(
            Net_NetProvider_RemoteAdAdd(
                net,
                &addr,
                &addr,
                1,                          // this should get from somewhere
                fake_Net_RandomNumber(0),   // must match host's Net::RandomNumber
                net->program,
                net->version,
                &game_data,
                1,                          // not important
                12,                         // not important
                0,                          // not important
                NULL,                       // ???
                1                           // ???
            ),
            "quicktest",
            player_name,
            0
        );

        // menu
        auto glue_mgr = CGlueMgr_Get();
        NetRegisterEvent(0x40090078, 6, glue_mgr->menu, 0);
        NetRegisterEvent(0x40090078, 6, glue_mgr->menu, 1);

        return;
    }
    return real_CGlueMgr_SetGlueScreen(a1, a2);
}
#pragma endregion

bool init_game() {
    // get base address
    base = (uint32_t)GetModuleHandleA("Game.dll");
    if (!base)
        return false;

    // get timestamp (for version check)
    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nt_header = (IMAGE_NT_HEADERS*)((uint32_t)dos_header + dos_header->e_lfanew);
    uint32_t timestap = nt_header->FileHeader.TimeDateStamp;

    switch (timestap) {
    case 0x4B88323B:
        // 1.24.4.6387
        WriteMemory((uint32_t)&SRegLoadString                           , base + 0x6EBD58);
        WriteMemory((uint32_t)&SMemFree                                 , base + 0x6EBCF8);
        WriteMemory((uint32_t)&PropGet                                  , base + 0x4C3FD0);
        WriteMemory((uint32_t)&CGlueMgr_Get                             , base + 0x593B30);
        WriteMemory((uint32_t)&CGlueMgr_SetGlueScreen                   , base + 0x593C90);
        WriteMemory((uint32_t)&CGameChatroom_OnDistFilesOutstanding     , base + 0x57BC70);
        WriteMemory((uint32_t)&CGameChatroom_OnPlayerJoin               , base + 0x57BD00);
        WriteMemory((uint32_t)&WorldOpenMapArchive                      , base + 0x00F2C0);
        WriteMemory((uint32_t)&WorldGetMapInfo                          , base + 0x01E6E0);
        WriteMemory((uint32_t)&NetInitializeProvider                    , base + 0x54FCB0);
        WriteMemory((uint32_t)&Net_NetProvider_RemoteAdAdd              , base + 0x65D0A0);
        WriteMemory((uint32_t)&NetGlueGameCreate                        , base + 0x5C57E0);
        WriteMemory((uint32_t)&NetGlueGameJoin                          , base + 0x5C58D0);
        WriteMemory((uint32_t)&NetRegisterEvent                         , base + 0x53FE50);
        WriteMemory((uint32_t)&NetStartGame                             , base + 0x53FFA0);
        WriteMemory((uint32_t)&NetLeaveGame                             , base + 0x54D2E0);
        WriteMemory((uint32_t)&Net_RandomNumber                         , base + 0x664440);
        WriteMemory((uint32_t)&CGameWar3_LoadMapSetup                   , base + 0x3AFAC0);
        break;
    case 0x4D83BB00:
        // 1.26.0.6401
        WriteMemory((uint32_t)&SRegLoadString                           , base + 0x6EB5B8);
        WriteMemory((uint32_t)&SMemFree                                 , base + 0x6EB558);
        WriteMemory((uint32_t)&PropGet                                  , base + 0x4C34D0);
        WriteMemory((uint32_t)&CGlueMgr_Get                             , base + 0x593390);
        WriteMemory((uint32_t)&CGlueMgr_SetGlueScreen                   , base + 0x5934F0);
        WriteMemory((uint32_t)&CGameChatroom_OnDistFilesOutstanding     , base + 0x57AFD0);
        WriteMemory((uint32_t)&CGameChatroom_OnPlayerJoin               , base + 0x57B060);
        WriteMemory((uint32_t)&WorldOpenMapArchive                      , base + 0x00E580);
        WriteMemory((uint32_t)&WorldGetMapInfo                          , base + 0x01D9A0);
        WriteMemory((uint32_t)&NetInitializeProvider                    , base + 0x54F1B0);
        WriteMemory((uint32_t)&Net_NetProvider_RemoteAdAdd              , base + 0x65C900);
        WriteMemory((uint32_t)&NetGlueGameCreate                        , base + 0x5C5040);
        WriteMemory((uint32_t)&NetGlueGameJoin                          , base + 0x5C5130);
        WriteMemory((uint32_t)&NetRegisterEvent                         , base + 0x53F350);
        WriteMemory((uint32_t)&NetStartGame                             , base + 0x53F4A0);
        WriteMemory((uint32_t)&NetLeaveGame                             , base + 0x54C7E0);
        WriteMemory((uint32_t)&Net_RandomNumber                         , base + 0x663CA0);
        WriteMemory((uint32_t)&CGameWar3_LoadMapSetup                   , base + 0x3AEF80);
        break;
    case 0x56BD0E1C:
        // 1.27.0.52240
        WriteMemory((uint32_t)&SRegLoadString                           , base + 0x120640);
        WriteMemory((uint32_t)&SMemFree                                 , base + 0x1205CE);
        WriteMemory((uint32_t)&PropGet                                  , base + 0x04EFB0);
        WriteMemory((uint32_t)&CGlueMgr_Get                             , base + 0x2C0920);
        WriteMemory((uint32_t)&CGlueMgr_SetGlueScreen                   , base + 0x2E6520);
        WriteMemory((uint32_t)&CGameChatroom_OnDistFilesOutstanding     , base + 0x2CE620);
        WriteMemory((uint32_t)&CGameChatroom_OnPlayerJoin               , base + 0x2DA340);
        WriteMemory((uint32_t)&WorldOpenMapArchive                      , base + 0x76ED90);
        WriteMemory((uint32_t)&WorldGetMapInfo                          , base + 0x76E060);
        WriteMemory((uint32_t)&NetInitializeProvider                    , base + 0x30E610);
        WriteMemory((uint32_t)&Net_NetProvider_RemoteAdAdd              , base + 0x851290);
        WriteMemory((uint32_t)&NetGlueGameCreate                        , base + 0x283320);
        WriteMemory((uint32_t)&NetGlueGameJoin                          , base + 0x283430);
        WriteMemory((uint32_t)&NetRegisterEvent                         , base + 0x30EDA0);
        WriteMemory((uint32_t)&NetStartGame                             , base + 0x30F960);
        WriteMemory((uint32_t)&NetLeaveGame                             , base + 0x30E9C0);
        WriteMemory((uint32_t)&Net_RandomNumber                         , base + 0x845840);
        WriteMemory((uint32_t)&CGameWar3_LoadMapSetup                   , base + 0x1C60A0);
        break;
    case 0x5956EFD4:
        // 1.28.5.7680
        WriteMemory((uint32_t)&SRegLoadString                           , base + 0x0A5FFA);
        WriteMemory((uint32_t)&SMemFree                                 , base + 0x0A5F88);
        WriteMemory((uint32_t)&PropGet                                  , base + 0x095DD0);
        WriteMemory((uint32_t)&CGlueMgr_Get                             , base + 0x3112A0);
        WriteMemory((uint32_t)&CGlueMgr_SetGlueScreen                   , base + 0x337240);
        WriteMemory((uint32_t)&CGameChatroom_OnDistFilesOutstanding     , base + 0x31ED80);
        WriteMemory((uint32_t)&CGameChatroom_OnPlayerJoin               , base + 0x32AFC0);
        WriteMemory((uint32_t)&WorldOpenMapArchive                      , base + 0x7C0680);
        WriteMemory((uint32_t)&WorldGetMapInfo                          , base + 0x7BF9B0);
        WriteMemory((uint32_t)&NetInitializeProvider                    , base + 0x35FA10);
        WriteMemory((uint32_t)&Net_NetProvider_RemoteAdAdd              , base + 0x92FB00);
        WriteMemory((uint32_t)&NetGlueGameCreate                        , base + 0x2D3510);
        WriteMemory((uint32_t)&NetGlueGameJoin                          , base + 0x2D3620);
        WriteMemory((uint32_t)&NetRegisterEvent                         , base + 0x3601D0);
        WriteMemory((uint32_t)&NetStartGame                             , base + 0x360D90);
        WriteMemory((uint32_t)&NetLeaveGame                             , base + 0x35FDF0);
        WriteMemory((uint32_t)&Net_RandomNumber                         , base + 0x924090);
        WriteMemory((uint32_t)&CGameWar3_LoadMapSetup                   , base + 0x2164F0);
        break;
    default:
        return false;
    }

    SRegLoadString("WorldEdit", "Test Map - Player Profile", 0, player_name, sizeof(player_name));

    if (std::string(GetCommandLineA()).find("-host") != std::string::npos) {
        // prepare hook function address
        WriteMemory((uint32_t)&real_CGlueMgr_SetGlueScreen                  , CGlueMgr_SetGlueScreen);
        WriteMemory((uint32_t)&real_CGameChatroom_OnDistFilesOutstanding    , CGameChatroom_OnDistFilesOutstanding);
        WriteMemory((uint32_t)&real_CGameChatroom_OnPlayerJoin              , CGameChatroom_OnPlayerJoin);
        WriteMemory((uint32_t)&real_Net_RandomNumber                        , Net_RandomNumber);
        WriteMemory((uint32_t)&real_NetLeaveGame                            , NetLeaveGame);

        // install hook
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)real_CGlueMgr_SetGlueScreen, fake_CGlueMgr_SetGlueScreen_host);
        DetourAttach(&(PVOID&)real_CGameChatroom_OnDistFilesOutstanding, fake_CGameChatroom_OnDistFilesOutstanding);
        DetourAttach(&(PVOID&)real_CGameChatroom_OnPlayerJoin, fake_CGameChatroom_OnPlayerJoin);
        DetourAttach(&(PVOID&)real_Net_RandomNumber, fake_Net_RandomNumber);
        DetourAttach(&(PVOID&)real_NetLeaveGame, fake_NetLeaveGame);
        DetourTransactionCommit();

        // parse args
        int argc;
        auto argv = CommandLineToArgvW(GetCommandLineW(), &argc);

        for (int i = 0; i < argc - 2; i++)
            if (wcscmp(argv[i], L"-host") == 0) {
                player_count = _wtoi(argv[i + 1]);
                filepath = w2a(argv[i + 2]);
            }
        
        // create event
        hEvent[0] = CreateEventA(NULL, true, false, "war3_quicktest0");
        hEvent[1] = CreateEventA(NULL, true, false, "war3_quicktest1");
        
        real_SEH_handler = SetUnhandledExceptionFilter(fake_SEH_handler);
    }
    else if (std::string(GetCommandLineA()).find("-join") != std::string::npos) {
        // open event
        while (hEvent[0] == NULL) {
            hEvent[0] = OpenEventA(SYNCHRONIZE, false, "war3_quicktest0");
            Sleep(1);
        }
        while (hEvent[1] == NULL) {
            hEvent[1] = OpenEventA(SYNCHRONIZE, false, "war3_quicktest1");
            Sleep(1);
        }
        // get status (ready / failed)
        if (WaitForMultipleObjects(2, hEvent, false, INFINITE) != WAIT_OBJECT_0)
            TerminateProcess(GetCurrentProcess(), 1);

        // prepare hook function address
        WriteMemory((uint32_t)&real_CGlueMgr_SetGlueScreen, CGlueMgr_SetGlueScreen);

        // install hook
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)real_CGlueMgr_SetGlueScreen, fake_CGlueMgr_SetGlueScreen_join);
        DetourTransactionCommit();
    }
    else
        return false;
    return true;
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);
        return init_game();
    }
    else if (reason == DLL_PROCESS_DETACH) {
        
    }
    return true;
}