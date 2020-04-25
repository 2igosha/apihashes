/*
 * =====================================================================================
 *       Filename:  apihashes_ida.cpp
 *    Description:  Simple IDA plugin to search for API hashes 
 *        Created:  22.04.2020 16:14:55
 *         Author:  Igor Kuznetsov (igosha), 2igosha@gmail.com
 * =====================================================================================
 */
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <bytes.hpp>
#include <name.hpp>
#include <moves.hpp>
#include <auto.hpp>
#include <diskio.hpp>
#include <inttypes.h>
#include <unordered_map>
#include <string>
#include <vector>

static const char help[] = "Api Hashes";
static const char *comment = help;
static const char *wanted_name = help;
static const char wanted_hotkey[] = "";


uint32_t HashAPI(const std::string& libName, const std::string& name){
    uint32_t result = 0;
    for (int i = 0; i < libName.size(); i++){
        uint8_t c = static_cast<uint8_t>(libName[i]);
        if ( c > 0x60 ) {
            c -= 0x20;
        }
        result = ( ( result >> 0xD ) | ( result << ( 32 - 0xD ) ) ) + c;
        result = ( ( result >> 0xD ) | ( result << ( 32 - 0xD ) ) ); // zero char for UTF-16
    }
    // That's for the terminating zero WORD
    result = ( ( result >> 0xD ) | ( result << ( 32 - 0xD ) ) );
    result = ( ( result >> 0xD ) | ( result << ( 32 - 0xD ) ) );

    uint32_t hash2 = 0;
    for (int i = 0; i < name.size(); i++){
        uint8_t c = static_cast<uint8_t>(name[i]);
        hash2 = ( ( hash2 >> 0xD ) | ( hash2 << ( 32 - 0xD ) ) ) + c;
    }
    result += ( ( hash2 >> 0xD ) | ( hash2 << ( 32 - 0xD ) ) );
    msg("hash \"%s\", \"%s\" = 0x%X\n", libName.c_str(), name.c_str(), result);
    return result;
}

bool idaapi run(size_t){
    // Load the names and hash them
    const char* fname = ask_file(false, NULL, "*.*", "Please specify the API list file");
    if ( fname == nullptr ) {
        return true;
    }
    qstring qlibName;
    if ( !ask_str(&qlibName, HIST_FILE, "Please specify the dll name") ) {
        return true;
    }
    std::string libName = qlibName.c_str();
    FILE *f = qfopen(fname, "rt");
    if ( f == nullptr ) {
        return true;
    }
    std::vector<char> buf(1024);
    std::unordered_map<uint32_t, std::string> hashes;
    while ( qfgets(&buf[0], buf.size(), f) ) {
        std::string line = reinterpret_cast<char*>(&buf[0]);
        while ( line.back() == '\r' || line.back() == '\n' ) {
            line.pop_back();
        }
        hashes[HashAPI(libName, line)] = line;
    }
    qfclose(f);

    // Search for all opcodes that have operands matching the hash values
    for (ea_t ea = inf.min_ea; ea < inf.max_ea; ea = next_addr(ea)){
        flags_t flg = get_flags(ea);
        if ( !is_code(flg) ) {
            continue;
        }
		insn_t		cmd;
		if ( decode_insn(&cmd, ea) <= 0 ) {
            continue;
        }
        bool found = false;
        for (size_t idx = 0; idx < UA_MAXOP && !found; ++idx) {
            if ( cmd.ops[idx].type != o_imm ||
                    cmd.ops[idx].value == 0 ) {
                continue;
            }
            if ( hashes.find(cmd.ops[idx].value) != hashes.end() ) {
                std::string name = hashes[cmd.ops[idx].value];
                msg("[%" PRIX64 "] Found API hash for %s\n", (uint64_t)ea, name.c_str());
                set_cmt(ea, name.c_str(), false);
            }
        }
    }

    return true;
}

int idaapi init(){
    return PLUGIN_KEEP;
}

void term(){
}

plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_PROC,          
  init,                
  term,               
  run,                  
  comment,               help,                 
  wanted_name,          
  wanted_hotkey        
};
