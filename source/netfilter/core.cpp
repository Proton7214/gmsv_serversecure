#include "core.hpp"
#include "baseserver.hpp"
#include "clientmanager.hpp"
#include <iostream>

#include <GarrysMod/FactoryLoader.hpp>
#include <GarrysMod/FunctionPointers.hpp>
#include <GarrysMod/InterfacePointers.hpp>
#include <GarrysMod/Lua/Interface.h>
#include <GarrysMod/Lua/LuaInterface.h>
#include <GarrysMod/Lua/Helpers.hpp>
#include <Platform.hpp>

#include <detouring/classproxy.hpp>
#include <detouring/hook.hpp>

#include <bitbuf.h>
#include <checksum_sha1.h>
#include <dbg.h>
#include <eiface.h>
#include <filesystem_stdio.h>
#include <game/server/iplayerinfo.h>
#include <iserver.h>
#include <steam/steam_gameserver.h>
#include <threadtools.h>
#include <utlvector.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <queue>
#include <random>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

#if defined SYSTEM_WINDOWS

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define SERVERSECURE_CALLING_CONVENTION __stdcall

#include <WinSock2.h>
#include <Ws2tcpip.h>
#include <processthreadsapi.h>
#include <windows.h>

using ssize_t = int32_t;
using recvlen_t = int32_t;

#elif defined SYSTEM_POSIX

#define SERVERSECURE_CALLING_CONVENTION

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#if defined SYSTEM_LINUX

#include <sys/prctl.h>

#elif defined SYSTEM_MACOSX

#include <pthread.h>

#endif

typedef int32_t SOCKET;
typedef size_t recvlen_t;

static const SOCKET INVALID_SOCKET = -1;

#endif

struct netsocket_t {
  int32_t nPort;
  bool bListening;
  int32_t hUDP;
  int32_t hTCP;
};

struct server_tags_t {
  std::string gm;
  std::string gmws;
  std::string gmc;
  std::string loc;
  std::string ver;
};

struct reply_info_t {
  bool dontsend;
  std::string server_name;
  std::string map_name;
  std::string game_dir;
  std::string game_name;
  std::string game_version;
  int32_t current_clients = 0;
  int32_t max_clients = 0;
  int32_t fake_clients = 0;
  char server_type;
  char os_type;
  bool password;
  bool secure;
  int32_t udp_port = 0;
  server_tags_t tags;
  int appid;
  uint64_t steamid;
};

struct player_t {
  byte index;
  std::string name;
  double score;
  double time;
};

struct reply_player_t {
  bool dontsend;
  bool senddefault;

  byte count;
  std::vector<player_t> players;
};

GarrysMod::Lua::ILuaBase *server_lua = nullptr;

namespace netfilter {
class Core {
public:
  struct packet_t {
    packet_t() : address(), address_size(sizeof(address)) {}

    sockaddr_in address;
    socklen_t address_size;
    std::vector<uint8_t> buffer;
  };

  explicit Core(const char *game_version)
      : server(InterfacePointers::Server()) {

    if (server == nullptr) {
      throw std::runtime_error("failed to dereference IServer");
    }

    if (!server_loader.IsValid()) {
      throw std::runtime_error("unable to get server factory");
    }

    ICvar *icvar = InterfacePointers::Cvar();
    if (icvar != nullptr) {
      sv_visiblemaxplayers = icvar->FindVar("sv_visiblemaxplayers");
      sv_location = icvar->FindVar("sv_location");
    }

    if (sv_visiblemaxplayers == nullptr) {
      Warning(
          "[ServerSecure] Failed to get \"sv_visiblemaxplayers\" convar!\n");
    }

    if (sv_location == nullptr) {
      Warning("[ServerSecure] Failed to get \"sv_location\" convar!\n");
    }

    gamedll = InterfacePointers::ServerGameDLL();
    if (gamedll == nullptr) {
      throw std::runtime_error(
          "failed to load required IServerGameDLL interface");
    }

    engine_server = InterfacePointers::VEngineServer();
    if (engine_server == nullptr) {
      throw std::runtime_error(
          "failed to load required IVEngineServer interface");
    }

    filesystem = InterfacePointers::FileSystem();
    if (filesystem == nullptr) {
      throw std::runtime_error("failed to initialize IFileSystem");
    }

    const FunctionPointers::GMOD_GetNetSocket_t GetNetSocket =
        FunctionPointers::GMOD_GetNetSocket();
    if (GetNetSocket != nullptr) {
      const netsocket_t *net_socket = GetNetSocket(1);
      if (net_socket != nullptr) {
        game_socket = net_socket->hUDP;
      }
    }

    if (game_socket == INVALID_SOCKET) {
      throw std::runtime_error("got an invalid server socket");
    }

    if (!recvfrom_hook.Enable()) {
      throw std::runtime_error("failed to detour recvfrom");
    }

    BuildStaticReplyInfo(game_version);
  }

  ~Core() { recvfrom_hook.Disable(); }

  Core(const Core &) = delete;
  Core(Core &&) = delete;

  Core &operator=(const Core &) = delete;
  Core &operator=(Core &&) = delete;

  void BuildStaticReplyInfo(const char *game_version) {
    reply_info.game_name = gamedll->GetGameDescription();

    {
      reply_info.game_dir.resize(256);
      engine_server->GetGameDir(
          &reply_info.game_dir[0],
          static_cast<int32_t>(reply_info.game_dir.size()));
      reply_info.game_dir.resize(std::strlen(reply_info.game_dir.c_str()));

      size_t pos = reply_info.game_dir.find_last_of("\\/");
      if (pos != std::string::npos) {
        reply_info.game_dir.erase(0, pos + 1);
      }
    }

    reply_info.max_clients = server->GetMaxClients();

    reply_info.udp_port = server->GetUDPPort();

    {
      const IGamemodeSystem::Information &gamemode =
          dynamic_cast<CFileSystem_Stdio *>(filesystem)->Gamemodes()->Active();

      if (!gamemode.name.empty()) {
        reply_info.tags.gm = gamemode.name;
      } else {
        reply_info.tags.gm.clear();
      }

      if (gamemode.workshopid != 0) {
        reply_info.tags.gmws = std::to_string(gamemode.workshopid);
      } else {
        reply_info.tags.gmws.clear();
      }

      if (!gamemode.category.empty()) {
        reply_info.tags.gmc = gamemode.category;
      } else {
        reply_info.tags.gmc.clear();
      }

      if (game_version != nullptr) {
        reply_info.tags.ver = game_version;
      }
    }

    {
      FileHandle_t file = filesystem->Open("steam.inf", "r", "GAME");
      if (file == nullptr) {
        reply_info.game_version = default_game_version;
        DevWarning("[ServerSecure] Error opening steam.inf\n");
        return;
      }

      std::array<char, 256> buff{};
      bool failed =
          filesystem->ReadLine(buff.data(), buff.size(), file) == nullptr;
      filesystem->Close(file);
      if (failed) {
        reply_info.game_version = default_game_version;
        DevWarning("[ServerSecure] Failed reading steam.inf\n");
        return;
      }

      reply_info.game_version = &buff[13];

      size_t pos = reply_info.game_version.find_first_of("\r\n");
      if (pos != std::string::npos) {
        reply_info.game_version.erase(pos);
      }
    }
  }

  static std::string ConcatenateTags(const server_tags_t &tags) {
    std::string strtags;

    if (!tags.gm.empty()) {
      strtags += "gm:";
      strtags += tags.gm;
    }

    if (!tags.gmws.empty()) {
      strtags += strtags.empty() ? "gmws:" : " gmws:";
      strtags += tags.gmws;
    }

    if (!tags.gmc.empty()) {
      strtags += strtags.empty() ? "gmc:" : " gmc:";
      strtags += tags.gmc;
    }

    if (!tags.loc.empty()) {
      strtags += strtags.empty() ? "loc:" : " loc:";
      strtags += tags.loc;
    }

    if (!tags.ver.empty()) {
      strtags += strtags.empty() ? "ver:" : " ver:";
      strtags += tags.ver;
    }

    return strtags;
  }

  void UpdateReplyInfo() {
    reply_info.server_name = server->GetName();
    reply_info.map_name = server->GetMapName();

    reply_info.appid = engine_server->GetAppID();
    reply_info.current_clients = server->GetNumClients();
    reply_info.fake_clients = server->GetNumFakeClients();
    reply_info.password = server->GetPassword() != nullptr ? 1 : 0;

    if (gameserver == nullptr)
      gameserver = SteamGameServer();

    if (gameserver != nullptr)
      reply_info.secure = gameserver->BSecure();

    if (sv_location != nullptr)
      reply_info.tags.loc = sv_location->GetString();
    else
      reply_info.tags.loc.clear();

    const CSteamID *steamid = engine_server->GetGameServerSteamID();

    if (steamid)
      reply_info.steamid = steamid->ConvertToUint64();
  }

  void BuildReplyInfo(reply_info_t info) {
    info_cache_packet.Reset();

    info_cache_packet.WriteLong(-1);
    info_cache_packet.WriteByte('I');
    info_cache_packet.WriteByte(default_proto_version);

    info_cache_packet.WriteString(info.server_name.c_str());
    info_cache_packet.WriteString(info.map_name.c_str());
    info_cache_packet.WriteString(info.game_dir.c_str());
    info_cache_packet.WriteString(info.game_name.c_str());

    info_cache_packet.WriteShort(info.appid);

    info_cache_packet.WriteByte(info.current_clients);
    info_cache_packet.WriteByte(info.max_clients);
    info_cache_packet.WriteByte(info.fake_clients);
    info_cache_packet.WriteByte(info.server_type);
    info_cache_packet.WriteByte(info.os_type);
    info_cache_packet.WriteByte(info.password);

    info_cache_packet.WriteByte(info.secure);
    info_cache_packet.WriteString(info.game_version.c_str());

    const std::string tags = ConcatenateTags(info.tags);
    const bool notags = tags.empty();
    info_cache_packet.WriteByte(0x80 | 0x110 | (notags ? 0x00 : 0x20) | 0x01);
    info_cache_packet.WriteShort(info.udp_port);
    info_cache_packet.WriteLongLong(info.steamid);

    if (!notags)
      info_cache_packet.WriteString(tags.c_str());

    info_cache_packet.WriteLongLong(info.appid);
  }

  void BuildReplyPlayer(reply_player_t info) {
    player_cache_packet.Reset();

    player_cache_packet.WriteLong(-1);
    player_cache_packet.WriteByte('D');

    player_cache_packet.WriteByte(info.count);

    for (int c = 0; c < info.count; c++) {
      player_t player = info.players[c];
      player_cache_packet.WriteByte(c);
      player_cache_packet.WriteString(player.name.c_str());
      player_cache_packet.WriteLong(player.score);
      player_cache_packet.WriteFloat(player.time);
    }
  }

  void SetFirewallWhitelistState(const bool enabled) {
    firewall_whitelist_enabled = enabled;
  }

  // Whitelisted IPs bytes need to be in network order (big endian)
  void AddWhitelistIP(const uint32_t address) {
    firewall_whitelist.insert(address);
  }

  void RemoveWhitelistIP(const uint32_t address) {
    firewall_whitelist.erase(address);
  }

  void ResetWhitelist() {
    std::unordered_set<uint32_t>().swap(firewall_whitelist);
  }

  void SetFirewallBlacklistState(const bool enabled) {
    firewall_blacklist_enabled = enabled;
  }

  // Blacklisted IPs bytes need to be in network order (big endian)
  void AddBlacklistIP(const uint32_t address) {
    firewall_blacklist.insert(address);
  }

  void RemoveBlacklistIP(const uint32_t address) {
    firewall_blacklist.erase(address);
  }

  void ResetBlacklist() {
    std::unordered_set<uint32_t>().swap(firewall_blacklist);
  }

  void SetPacketValidationState(const bool enabled) {
    packet_validation_enabled = enabled;
  }

  void SetInfoCacheState(const bool enabled) { info_cache_enabled = enabled; }

  void SetInfoCacheTime(const uint32_t time) { info_cache_time = time; }

  bool PopPacketFromSamplingQueue(packet_t& p) { return false; }

  ClientManager &GetClientManager() { return client_manager; }

  static std::unique_ptr<Core> Singleton;

private:
  enum class PacketType { Invalid = -1, Good, Info, Masterserver, Player };

  using recvfrom_t = ssize_t(SERVERSECURE_CALLING_CONVENTION *)(
      SOCKET, void *, recvlen_t, int32_t, sockaddr *, socklen_t *);

#if defined SYSTEM_WINDOWS

  static constexpr char operating_system_char = 'w';

#elif defined SYSTEM_POSIX

  static constexpr char operating_system_char = 'l';

#elif defined SYSTEM_MACOSX

  static constexpr char operating_system_char = 'm';

#endif
  static constexpr std::string_view default_game_version = "2020.10.14";
  static constexpr uint8_t default_proto_version = 17;

  static constexpr size_t packet_sampling_max_queue = 50;

  // Max size needed to contain a Steam authentication key (both server and
  // client)
  static constexpr int16_t STEAM_KEYSIZE = 2048;

  // Connection from client is using a WON authenticated certificate
  static constexpr int32_t PROTOCOL_AUTHCERTIFICATE = 0x01;
  // Connection from client is using hashed CD key because WON comm. channel was
  // unreachable
  static constexpr int32_t PROTOCOL_HASHEDCDKEY = 0x02;
  // Steam certificates
  static constexpr int32_t PROTOCOL_STEAM = 0x03;
  // Last valid protocol
  static constexpr int32_t PROTOCOL_LASTVALID = 0x03;

  static constexpr int32_t MAX_RANDOM_RANGE = 0x7FFFFFFFUL;

  IServer *server = nullptr;

  ISteamGameServer *gameserver = nullptr;

  SourceSDK::FactoryLoader icvar_loader = SourceSDK::FactoryLoader("vstdlib");
  ConVar *sv_visiblemaxplayers = nullptr;
  ConVar *sv_location = nullptr;

  SourceSDK::ModuleLoader dedicated_loader =
      SourceSDK::ModuleLoader("dedicated");
  SourceSDK::FactoryLoader server_loader = SourceSDK::FactoryLoader("server");

#ifdef PLATFORM_WINDOWS

  Detouring::Hook recvfrom_hook = Detouring::Hook(
      "ws2_32", "recvfrom", reinterpret_cast<void *>(recvfrom_detour));

#else

  Detouring::Hook recvfrom_hook =
      Detouring::Hook("recvfrom", reinterpret_cast<void *>(recvfrom_detour));

#endif

  SOCKET game_socket = INVALID_SOCKET;

  bool packet_validation_enabled = false;

  bool firewall_whitelist_enabled = false;
  std::unordered_set<uint32_t> firewall_whitelist;

  bool firewall_blacklist_enabled = false;
  std::unordered_set<uint32_t> firewall_blacklist;

  bool info_cache_enabled = false;
  reply_info_t reply_info;
  std::array<char, 1024> info_cache_buffer{};
  bf_write info_cache_packet = bf_write(
      info_cache_buffer.data(), static_cast<int32_t>(info_cache_buffer.size()));
  uint32_t info_cache_last_update = 0;
  uint32_t info_cache_time = 5;

  reply_player_t reply_player;
  std::array<char, 1024 * 5> player_cache_buffer{};
  bf_write player_cache_packet =
      bf_write(player_cache_buffer.data(),
               static_cast<int32_t>(player_cache_buffer.size()));

  ClientManager client_manager;

  bool packet_sampling_enabled = false;
  std::queue<packet_t> packet_sampling_queue;

  IServerGameDLL *gamedll = nullptr;
  IVEngineServer *engine_server = nullptr;
  IFileSystem *filesystem = nullptr;

  static inline const char *IPToString(const in_addr &addr) {
    static std::array<char, INET_ADDRSTRLEN> buffer{};
    const char *str = inet_ntop(AF_INET, &addr, buffer.data(), buffer.size());
    if (str == nullptr) {
      return "unknown";
    }

    return str;
  }

  reply_info_t CallInfoHook(const sockaddr_in &from) {
    if (server_lua->Top() > 0)
      return reply_info;

    char hook[] = "A2S_INFO";

    int32_t funcs = LuaHelpers::PushHookRun(server_lua, hook);

    if (funcs == 0)
      return reply_info;

    server_lua->PushString(IPToString(from.sin_addr));
    server_lua->PushNumber(from.sin_port);

    server_lua->CreateTable();

    server_lua->PushString(reply_info.server_name.c_str());
    server_lua->SetField(-2, "name");
    server_lua->PushString(reply_info.map_name.c_str());
    server_lua->SetField(-2, "map");
    server_lua->PushString(reply_info.game_dir.c_str());
    server_lua->SetField(-2, "folder");
    server_lua->PushString(reply_info.game_name.c_str());
    server_lua->SetField(-2, "game");
    server_lua->PushString(reply_info.game_version.c_str());
    server_lua->SetField(-2, "version");
    server_lua->PushNumber(reply_info.current_clients);
    server_lua->SetField(-2, "players");
    server_lua->PushNumber(reply_info.max_clients);
    server_lua->SetField(-2, "maxplayers");
    server_lua->PushNumber(reply_info.fake_clients);
    server_lua->SetField(-2, "bots");
    server_lua->PushString(&reply_info.server_type);
    server_lua->SetField(-2, "servertype");
    server_lua->PushString(&reply_info.os_type);
    server_lua->SetField(-2, "os");
    server_lua->PushBool(reply_info.password);
    server_lua->SetField(-2, "password");
    server_lua->PushBool(reply_info.secure);
    server_lua->SetField(-2, "secure");
    server_lua->PushNumber(reply_info.udp_port);
    server_lua->SetField(-2, "port");
    server_lua->PushNumber(reply_info.appid);
    server_lua->SetField(-2, "appid");
    server_lua->CreateTable();
    server_lua->PushString(reply_info.tags.gm.c_str());
    server_lua->SetField(-2, "gm");
    server_lua->PushString(reply_info.tags.gmws.c_str());
    server_lua->SetField(-2, "gmws");
    server_lua->PushString(reply_info.tags.gmc.c_str());
    server_lua->SetField(-2, "gmc");
    server_lua->PushString(reply_info.tags.loc.c_str());
    server_lua->SetField(-2, "loc");
    server_lua->PushString(reply_info.tags.ver.c_str());
    server_lua->SetField(-2, "ver");
    server_lua->SetField(-2, "tags");

    std::string steamid = std::to_string(reply_info.steamid);
    server_lua->PushString(steamid.c_str());
    server_lua->SetField(-2, "steamid");

    LuaHelpers::CallHookRun(server_lua, 3, 1);

    reply_info_t setup;
    setup.dontsend = false;

    setup.server_name = reply_info.server_name;
    setup.map_name = reply_info.map_name;
    setup.game_dir = reply_info.game_dir;
    setup.game_version = reply_info.game_version;
    setup.game_name = reply_info.game_name;
    setup.current_clients = reply_info.current_clients;
    setup.max_clients = reply_info.max_clients;
    setup.fake_clients = reply_info.fake_clients;
    setup.server_type = reply_info.server_type;
    setup.os_type = reply_info.os_type;
    setup.password = reply_info.password;
    setup.secure = reply_info.secure;
    setup.game_version = reply_info.game_version;
    setup.udp_port = reply_info.udp_port;
    setup.tags = reply_info.tags;
    setup.appid = reply_info.appid;
    setup.steamid = reply_info.steamid;

    if (server_lua->IsType(-1, GarrysMod::Lua::Type::Bool)) {
      if (server_lua->GetBool(-1))
        setup = reply_info;
      else
        setup.dontsend = true;
    } else if (server_lua->IsType(-1, GarrysMod::Lua::Type::Table)) {
      server_lua->GetField(-1, "name");
      setup.server_name = server_lua->GetString(-1);
      server_lua->Pop(1);
      server_lua->GetField(-1, "map");
      setup.map_name = server_lua->GetString(-1);
      server_lua->Pop(1);
      server_lua->GetField(-1, "folder");
      setup.game_dir = server_lua->GetString(-1);
      server_lua->Pop(1);
      server_lua->GetField(-1, "game");
      setup.game_name = server_lua->GetString(-1);
      server_lua->Pop(1);
      server_lua->GetField(-1, "version");
      setup.game_version = server_lua->GetString(-1);
      server_lua->Pop(1);
      server_lua->GetField(-1, "players");
      setup.current_clients = server_lua->GetNumber(-1);
      server_lua->Pop(1);
      server_lua->GetField(-1, "maxplayers");
      setup.max_clients = server_lua->GetNumber(-1);
      server_lua->Pop(1);
      server_lua->GetField(-1, "bots");
      setup.fake_clients = server_lua->GetNumber(-1);
      server_lua->Pop(1);
      server_lua->GetField(-1, "servertype");
      setup.server_type = server_lua->GetString(-1)[0];
      server_lua->Pop(1);
      server_lua->GetField(-1, "os");
      setup.os_type = server_lua->GetString(-1)[0];
      server_lua->Pop(1);
      server_lua->GetField(-1, "password");
      setup.password = server_lua->GetBool(-1);
      server_lua->Pop(1);
      server_lua->GetField(-1, "secure");
      setup.secure = server_lua->GetBool(-1);
      server_lua->Pop(1);
      server_lua->GetField(-1, "port");
      setup.udp_port = server_lua->GetNumber(-1);
      server_lua->Pop(1);
      server_lua->GetField(-1, "appid");
      setup.appid = server_lua->GetNumber(-1);
      server_lua->Pop(1);
      server_lua->GetField(-1, "steamid");
      setup.steamid = strtoll(server_lua->GetString(-1), 0, 10);
      server_lua->Pop(1);
      server_lua->GetField(-1, "tags");
      {
          server_lua->GetField(-1, "gm");
          setup.tags.gm = server_lua->GetString(-1);
          server_lua->Pop(1);
          server_lua->GetField(-1, "gmws");
          setup.tags.gmws = server_lua->GetString(-1);
          server_lua->Pop(1);
          server_lua->GetField(-1, "gmc");
          setup.tags.gmc = server_lua->GetString(-1);
          server_lua->Pop(1);
          server_lua->GetField(-1, "loc");
          setup.tags.loc = server_lua->GetString(-1);
          server_lua->Pop(1);
          server_lua->GetField(-1, "ver");
          setup.tags.ver = server_lua->GetString(-1);
          server_lua->Pop(1);
      }
      server_lua->Pop(1);
    }

    server_lua->Pop(1);

    return setup;
  }

  reply_player_t CallPlayerHook(const sockaddr_in &from) {
    char hook[] = "A2S_PLAYER";

    reply_player_t players;
    players.dontsend = false;
    players.senddefault = true;

    if (server_lua->Top() > 0)
      return players;

    int32_t funcs = LuaHelpers::PushHookRun(server_lua, hook);

    if (funcs == 0)
      return players;

    server_lua->PushString(IPToString(from.sin_addr));
    server_lua->PushNumber(from.sin_port);

    LuaHelpers::CallHookRun(server_lua, 2, 1);

    if (server_lua->IsType(-1, GarrysMod::Lua::Type::Bool)) {
      if (!server_lua->GetBool(-1)) {
        players.senddefault = false;
        players.dontsend = true;
      }
    } else if (server_lua->IsType(-1, GarrysMod::Lua::Type::Table)) {
      players.senddefault = false;
      players.dontsend = false;

      int count = server_lua->ObjLen(-1);
      players.count = count;
      std::vector<player_t> list(count);

      for (int i = 0; i < count; i++) {
        player_t player;
        player.index = i;

        server_lua->PushNumber(i + 1);
        server_lua->GetTable(-2);

        server_lua->GetField(-1, "name");
        player.name = server_lua->GetString(-1);
        server_lua->Pop(1);
        server_lua->GetField(-1, "score");
        player.score = server_lua->GetNumber(-1);
        server_lua->Pop(1);
        server_lua->GetField(-1, "time");
        player.time = server_lua->GetNumber(-1);
        server_lua->Pop(1);

        list.at(i) = player;
        server_lua->Pop(1);
      }

      players.players = list;
    }

    server_lua->Pop(1);

    return players;
  }

  PacketType SendInfoCache(const sockaddr_in &from, uint32_t time) {
    if (time - info_cache_last_update >= info_cache_time) {
      UpdateReplyInfo();
      info_cache_last_update = time;
    }

    reply_info_t modified = CallInfoHook(from);
    if (modified.dontsend)
      return PacketType::Invalid;

    BuildReplyInfo(modified);

    sendto(game_socket, reinterpret_cast<char *>(info_cache_packet.GetData()),
           info_cache_packet.GetNumBytesWritten(), 0,
           reinterpret_cast<const sockaddr *>(&from), sizeof(from));

    DevMsg("[ServerSecure] Handled %s info request using cache\n",
           IPToString(from.sin_addr));

    return PacketType::Invalid; // we've handled it
  }

  PacketType HandleInfoQuery(const sockaddr_in &from) {
    const auto time = static_cast<uint32_t>(Plat_FloatTime());
    if (!client_manager.CheckIPRate(from.sin_addr.s_addr, time)) {
      DevWarning("[ServerSecure] Client %s hit rate limit\n",
                 IPToString(from.sin_addr));
      return PacketType::Invalid;
    }

    if (info_cache_enabled) {
      return SendInfoCache(from, time);
    }

    return PacketType::Good;
  }

  PacketType HandlePlayerQuery(const sockaddr_in &from) {
    reply_player_t players = CallPlayerHook(from);

    if (players.senddefault)
      return PacketType::Good;

    if (players.dontsend)
      return PacketType::Invalid;

    BuildReplyPlayer(players);

    sendto(game_socket, reinterpret_cast<char *>(player_cache_packet.GetData()),
           player_cache_packet.GetNumBytesWritten(), 0,
           reinterpret_cast<const sockaddr *>(&from), sizeof(from));

    return PacketType::Invalid;
  }

  PacketType ClassifyPacket(const uint8_t *data, int32_t len,
                            const sockaddr_in &from) const {
    if (len == 0) {
      DevWarning("[ServerSecure] Bad OOB! len: %d from %s\n", len,
                 IPToString(from.sin_addr));
      return PacketType::Invalid;
    }

    if (len < 5) {
      return PacketType::Good;
    }

    bf_read packet(data, len);
    const auto channel = static_cast<int32_t>(packet.ReadLong());
    if (channel == -2) {
      DevWarning("[ServerSecure] Bad OOB! len: %d, channel: 0x%X from %s\n",
                 len, channel, IPToString(from.sin_addr));
      return PacketType::Invalid;
    }

    if (channel != -1) {
      return PacketType::Good;
    }

    const auto type = static_cast<uint8_t>(packet.ReadByte());
    if (packet_validation_enabled) {
      switch (type) {
      case 'W': // server challenge request
      case 's': // master server challenge
        if (len > 100) {
          DevWarning("[ServerSecure] Bad OOB! len: %d, channel: 0x%X, type: %c "
                     "from %s\n",
                     len, channel, type, IPToString(from.sin_addr));
          return PacketType::Invalid;
        }

        if (len >= 18 &&
            strncmp(reinterpret_cast<const char *>(data + 5), "statusResponse",
                    14) == 0) {
          DevWarning("[ServerSecure] Bad OOB! len: %d, channel: 0x%X, type: %c "
                     "from %s\n",
                     len, channel, type, IPToString(from.sin_addr));
          return PacketType::Invalid;
        }

        return PacketType::Good;

      case 'T': // server info request (A2S_INFO)
        if ((len != 25 && len != 1200) ||
            strncmp(reinterpret_cast<const char *>(data + 5),
                    "Source Engine Query", 19) != 0) {
          DevWarning("[ServerSecure] Bad OOB! len: %d, channel: 0x%X, type: %c "
                     "from %s\n",
                     len, channel, type, IPToString(from.sin_addr));
          return PacketType::Invalid;
        }

        return PacketType::Info;

      case 'U': // player info request (A2S_PLAYER)
        return PacketType::Player;
      case 'V': // rules request (A2S_RULES)
        if (len != 9 && len != 1200) {
          DevWarning("[ServerSecure] Bad OOB! len: %d, channel: 0x%X, type: %c "
                     "from %s\n",
                     len, channel, type, IPToString(from.sin_addr));
          return PacketType::Invalid;
        }

        return PacketType::Good;

      case 'q': // connection handshake init
      case 'k': // steam auth packet
        DevMsg("[ServerSecure] Good OOB! len: %d, channel: 0x%X, type: %c from "
               "%s\n",
               len, channel, type, IPToString(from.sin_addr));
        return PacketType::Good;

      default:
        break;
      }

      DevWarning(
          "[ServerSecure] Bad OOB! len: %d, channel: 0x%X, type: %c from %s\n",
          len, channel, type, IPToString(from.sin_addr));
      return PacketType::Invalid;
    }

    return type == 'T' ? PacketType::Info
                       : (type == 'U' ? PacketType::Player : PacketType::Good);
  }

  bool IsAddressAllowed(const sockaddr_in &addr) {
    return (!firewall_whitelist_enabled ||
            firewall_whitelist.find(addr.sin_addr.s_addr) !=
                firewall_whitelist.end()) &&
           (!firewall_blacklist_enabled ||
            firewall_blacklist.find(addr.sin_addr.s_addr) ==
                firewall_blacklist.end());
  }

  static int32_t HandleNetError(int32_t value) {
    if (value == -1) {

#if defined SYSTEM_WINDOWS

      WSASetLastError(WSAEWOULDBLOCK);

#elif defined SYSTEM_POSIX

      errno = EWOULDBLOCK;

#endif
    }

    return value;
  }

  ssize_t ReceiveAndAnalyzePacket(SOCKET s, void *buf, recvlen_t buflen,
                                  int32_t flags, sockaddr *from,
                                  socklen_t *fromlen) {
    auto trampoline = recvfrom_hook.GetTrampoline<recvfrom_t>();
    if (trampoline == nullptr) {
      return -1;
    }

    const ssize_t len = trampoline(s, buf, buflen, flags, from, fromlen);
    DevMsg(
        "[ServerSecure] Called recvfrom on socket %d and received %ld bytes\n",
        s, len);
    if (len == -1) {
      return -1;
    }

    const uint8_t *buffer = reinterpret_cast<uint8_t *>(buf);

    const sockaddr_in &infrom = *reinterpret_cast<sockaddr_in *>(from);
    if (!IsAddressAllowed(infrom)) {
      return -1;
    }

    DevMsg("[ServerSecure] Address %s was allowed\n",
           IPToString(infrom.sin_addr));

    PacketType type = ClassifyPacket(buffer, len, infrom);

    if (type == PacketType::Info)
      type = HandleInfoQuery(infrom);

    if (type == PacketType::Player)
      type = HandlePlayerQuery(infrom);

    return type != PacketType::Invalid ? len : -1;
  }

  static ssize_t SERVERSECURE_CALLING_CONVENTION
  recvfrom_detour(SOCKET s, void *buf, recvlen_t buflen, int32_t flags,
                  sockaddr *from, socklen_t *fromlen) {
    return HandleNetError(Core::Singleton->ReceiveAndAnalyzePacket(
        s, buf, buflen, flags, from, fromlen));
  }
};

std::unique_ptr<Core> Core::Singleton;

LUA_FUNCTION_STATIC(EnableFirewallWhitelist) {
  LUA->CheckType(1, GarrysMod::Lua::Type::Bool);
  Core::Singleton->SetFirewallWhitelistState(LUA->GetBool(1));
  return 0;
}

// Whitelisted IPs bytes need to be in network order (big endian)
LUA_FUNCTION_STATIC(AddWhitelistIP) {
  LUA->CheckType(1, GarrysMod::Lua::Type::Number);
  Core::Singleton->AddWhitelistIP(static_cast<uint32_t>(LUA->GetNumber(1)));
  return 0;
}

LUA_FUNCTION_STATIC(RemoveWhitelistIP) {
  LUA->CheckType(1, GarrysMod::Lua::Type::Number);
  Core::Singleton->RemoveWhitelistIP(static_cast<uint32_t>(LUA->GetNumber(1)));
  return 0;
}

LUA_FUNCTION_STATIC(ResetWhitelist) {
  Core::Singleton->ResetWhitelist();
  return 0;
}

LUA_FUNCTION_STATIC(EnableFirewallBlacklist) {
  LUA->CheckType(1, GarrysMod::Lua::Type::Bool);
  Core::Singleton->SetFirewallBlacklistState(LUA->GetBool(1));
  return 0;
}

// Blacklisted IPs bytes need to be in network order (big endian)
LUA_FUNCTION_STATIC(AddBlacklistIP) {
  LUA->CheckType(1, GarrysMod::Lua::Type::Number);
  Core::Singleton->AddBlacklistIP(static_cast<uint32_t>(LUA->GetNumber(1)));
  return 0;
}

LUA_FUNCTION_STATIC(RemoveBlacklistIP) {
  LUA->CheckType(1, GarrysMod::Lua::Type::Number);
  Core::Singleton->RemoveBlacklistIP(static_cast<uint32_t>(LUA->GetNumber(1)));
  return 0;
}

LUA_FUNCTION_STATIC(ResetBlacklist) {
  Core::Singleton->ResetBlacklist();
  return 0;
}

LUA_FUNCTION_STATIC(EnablePacketValidation) {
  LUA->CheckType(1, GarrysMod::Lua::Type::Bool);
  Core::Singleton->SetPacketValidationState(LUA->GetBool(1));
  return 0;
}

LUA_FUNCTION_STATIC(EnableInfoCache) {
  LUA->CheckType(1, GarrysMod::Lua::Type::Bool);
  Core::Singleton->SetInfoCacheState(LUA->GetBool(1));
  return 0;
}

LUA_FUNCTION_STATIC(SetInfoCacheTime) {
  LUA->CheckType(1, GarrysMod::Lua::Type::Number);
  Core::Singleton->SetInfoCacheTime(static_cast<uint32_t>(LUA->GetNumber(1)));
  return 0;
}

LUA_FUNCTION_STATIC(RefreshInfoCache) {
  Core::Singleton->BuildStaticReplyInfo(nullptr);
  Core::Singleton->UpdateReplyInfo();
  return 0;
}

LUA_FUNCTION_STATIC(EnableQueryLimiter) {
  LUA->CheckType(1, GarrysMod::Lua::Type::Bool);
  Core::Singleton->GetClientManager().SetState(LUA->GetBool(1));
  return 0;
}

LUA_FUNCTION_STATIC(SetMaxQueriesWindow) {
  LUA->CheckType(1, GarrysMod::Lua::Type::Number);
  Core::Singleton->GetClientManager().SetMaxQueriesWindow(
      static_cast<uint32_t>(LUA->GetNumber(1)));
  return 0;
}

LUA_FUNCTION_STATIC(SetMaxQueriesPerSecond) {
  LUA->CheckType(1, GarrysMod::Lua::Type::Number);
  Core::Singleton->GetClientManager().SetMaxQueriesPerSecond(
      static_cast<uint32_t>(LUA->GetNumber(1)));
  return 0;
}

LUA_FUNCTION_STATIC(SetGlobalMaxQueriesPerSecond) {
  LUA->CheckType(1, GarrysMod::Lua::Type::Number);
  Core::Singleton->GetClientManager().SetGlobalMaxQueriesPerSecond(
      static_cast<uint32_t>(LUA->GetNumber(1)));
  return 0;
}

class CBaseServerProxy
    : public Detouring::ClassProxy<CBaseServer, CBaseServerProxy> {
private:
  using TargetClass = CBaseServer;
  using SubstituteClass = CBaseServerProxy;

public:
  explicit CBaseServerProxy(CBaseServer *baseserver) {
    Initialize(baseserver);
    Hook(&CBaseServer::CheckChallengeNr, &CBaseServerProxy::CheckChallengeNr);
    Hook(&CBaseServer::GetChallengeNr, &CBaseServerProxy::GetChallengeNr);
  }

  ~CBaseServerProxy() override {
    UnHook(&CBaseServer::CheckChallengeNr);
    UnHook(&CBaseServer::GetChallengeNr);
  }

  CBaseServerProxy(const CBaseServerProxy &) = delete;
  CBaseServerProxy(CBaseServerProxy &&) = delete;

  CBaseServerProxy &operator=(const CBaseServerProxy &) = delete;
  CBaseServerProxy &operator=(CBaseServerProxy &&) = delete;

  virtual bool CheckChallengeNr(netadr_t &adr, int nChallengeValue) {
    // See if the challenge is valid
    // Don't care if it is a local address.
    if (adr.IsLoopback()) {
      return true;
    }

    // X360TBD: network
    if (IsX360()) {
      return true;
    }

    UpdateChallengeIfNeeded();

    m_challenge[4] = adr.GetIPNetworkByteOrder();

    CSHA1 hasher;
    hasher.Update(reinterpret_cast<uint8_t *>(&m_challenge[0]),
                  sizeof(uint32_t) * m_challenge.size());
    hasher.Final();
    SHADigest_t hash = {0};
    hasher.GetHash(hash);
    if (reinterpret_cast<int *>(hash)[0] == nChallengeValue) {
      return true;
    }

    // try with the old random nonce
    m_previous_challenge[4] = adr.GetIPNetworkByteOrder();

    hasher.Reset();
    hasher.Update(reinterpret_cast<uint8_t *>(&m_previous_challenge[0]),
                  sizeof(uint32_t) * m_previous_challenge.size());
    hasher.Final();
    hasher.GetHash(hash);
    return reinterpret_cast<int *>(hash)[0] == nChallengeValue;
  }

  virtual int GetChallengeNr(netadr_t &adr) {
    UpdateChallengeIfNeeded();

    m_challenge[4] = adr.GetIPNetworkByteOrder();

    CSHA1 hasher;
    hasher.Update(reinterpret_cast<uint8_t *>(&m_challenge[0]),
                  sizeof(uint32_t) * m_challenge.size());
    hasher.Final();
    SHADigest_t hash = {0};
    hasher.GetHash(hash);
    return reinterpret_cast<int *>(hash)[0];
  }

  static void UpdateChallengeIfNeeded() {
    const double current_time = Plat_FloatTime();
    if (m_challenge_gen_time >= 0 &&
        current_time < m_challenge_gen_time + CHALLENGE_NONCE_LIFETIME) {
      return;
    }

    m_challenge_gen_time = current_time;
    m_previous_challenge.swap(m_challenge);

    m_challenge[0] = m_rng();
    m_challenge[1] = m_rng();
    m_challenge[2] = m_rng();
    m_challenge[3] = m_rng();
  }

  static std::mt19937 InitializeRNG() noexcept {
    try {
      return std::mt19937(std::random_device{}());
    } catch (const std::exception &e) {
      Warning("[ServerSecure] Failed to initialize RNG seed, falling back to "
              "less secure current time seed: %s\n",
              e.what());
      return std::mt19937(
          static_cast<uint32_t>(Plat_FloatTime() * 1000000 /* microseconds */));
    }
  }

  static std::mt19937 m_rng;
  static double m_challenge_gen_time;
  static std::array<uint32_t, 5> m_previous_challenge;
  static std::array<uint32_t, 5> m_challenge;

  static std::unique_ptr<CBaseServerProxy> Singleton;
};

std::mt19937 CBaseServerProxy::m_rng = CBaseServerProxy::InitializeRNG();
double CBaseServerProxy::m_challenge_gen_time = -1;
std::array<uint32_t, 5> CBaseServerProxy::m_previous_challenge;
std::array<uint32_t, 5> CBaseServerProxy::m_challenge;

std::unique_ptr<CBaseServerProxy> CBaseServerProxy::Singleton;

void Initialize(GarrysMod::Lua::ILuaBase *LUA) {
  server_lua = LUA;
  LUA->GetField(GarrysMod::Lua::INDEX_GLOBAL, "VERSION");
  const char *game_version = LUA->CheckString(-1);

  bool errored = false;
  try {
    Core::Singleton = std::make_unique<Core>(game_version);
  } catch (const std::exception &e) {
    errored = true;
    LUA->PushString(e.what());
  }

  if (errored) {
    LUA->Error();
  }

  LUA->Pop(1);

  auto *baseserver = dynamic_cast<CBaseServer *>(InterfacePointers::Server());
  if (baseserver != nullptr) {
    CBaseServerProxy::Singleton =
        std::make_unique<CBaseServerProxy>(baseserver);
  }

  LUA->PushCFunction(EnableFirewallWhitelist);
  LUA->SetField(-2, "EnableFirewallWhitelist");

  LUA->PushCFunction(AddWhitelistIP);
  LUA->SetField(-2, "AddWhitelistIP");

  LUA->PushCFunction(RemoveWhitelistIP);
  LUA->SetField(-2, "RemoveWhitelistIP");

  LUA->PushCFunction(ResetWhitelist);
  LUA->SetField(-2, "ResetWhitelist");

  LUA->PushCFunction(EnableFirewallBlacklist);
  LUA->SetField(-2, "EnableFirewallBlacklist");

  LUA->PushCFunction(AddBlacklistIP);
  LUA->SetField(-2, "AddBlacklistIP");

  LUA->PushCFunction(RemoveBlacklistIP);
  LUA->SetField(-2, "RemoveBlacklistIP");

  LUA->PushCFunction(ResetBlacklist);
  LUA->SetField(-2, "ResetBlacklist");

  LUA->PushCFunction(EnablePacketValidation);
  LUA->SetField(-2, "EnablePacketValidation");

  LUA->PushCFunction(EnableInfoCache);
  LUA->SetField(-2, "EnableInfoCache");

  LUA->PushCFunction(SetInfoCacheTime);
  LUA->SetField(-2, "SetInfoCacheTime");

  LUA->PushCFunction(RefreshInfoCache);
  LUA->SetField(-2, "RefreshInfoCache");

  LUA->PushCFunction(EnableQueryLimiter);
  LUA->SetField(-2, "EnableQueryLimiter");

  LUA->PushCFunction(SetMaxQueriesWindow);
  LUA->SetField(-2, "SetMaxQueriesWindow");

  LUA->PushCFunction(SetMaxQueriesPerSecond);
  LUA->SetField(-2, "SetMaxQueriesPerSecond");

  LUA->PushCFunction(SetGlobalMaxQueriesPerSecond);
  LUA->SetField(-2, "SetGlobalMaxQueriesPerSecond");
}

void Deinitialize() {
  CBaseServerProxy::Singleton.reset();
  Core::Singleton.reset();
}
} // namespace netfilter
