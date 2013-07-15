// tail-comodo, a console event monitor for the Comodo Firewall product
// Copyright (C) 2013 Jonas Tingeborn
//
// tail-comodo is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 2 of the License, or
// (at your option) any later version.
//
// tail-comodo is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with fail-comodo.  If not, see http://www.gnu.org/licenses/

#include <stdlib.h>
#include <stdio.h>
#include <io.h>
#include <string.h>
#include <windows.h>
#include "vendor\sqlite3.h"

#define VERSION "1.0"

#define NOT_FOUND -1

#define FOLLOW 2
#define ALL    3
#define LAST_N 4

#define ENV_VAR "TAIL_COMODO_FWDB"
#define SELECT_FIELDS "id,datetime(logdate),path,pid,protocol,direction,srcport,dstport,action,srcaddr,dstaddr"

typedef struct {
    int cmd;          // How we're to tail the log
    int c_recs;       // number of records from the end to display
    int sleep;        // polling sleep in seconds
    char* db_file;    // location of the Comodo sqlite db
    int verbose;      // Whether or not to be noisy
    sqlite3* db;      // The database handle, for reuse if applicable
    int _last_row_id; // To keep track of the last row read,updated by execute
} config;

typedef struct {
  int         id;
  const char* logdate;
  const char* path;
  int         pid;
  const char* protocol;
  const char* direction;
  const char* srcaddr;
  int         srcport;
  const char* dstaddr;
  int         dstport;
  char*       action;
} resultrow;

// Global opts, nneded so that the windows signal hook can get at it :(
config opts;

// UTILITY FUNCTIONS ========================================================

// Gracefully stop the app
void terminate(int exitcode) {
    if(opts.db != 0) {
        if(opts.verbose) printf("Closing DB connection\n");
        sqlite3_close_v2(opts.db);
    }
    exit(exitcode);
}

void error(const char* fmt, ...) {
    va_list args;
    char msg[1024];
    strcpy(msg,fmt);
    strcat(msg,"\n");

    va_start(args, fmt);
    vfprintf(stdout, msg, args);
    va_end(args);

    terminate(1);
}

int isdigits(char* s){
    int i, len=strlen(s), ret = TRUE;
    for(i=0; i<len; i++) {
        if(s[i] < '0' || s[i] > '9') 
            ret = FALSE;
    }
    return ret;
}

// Check if a file is readable
int readable(char* filename) {
    return ! ( _access( filename, 4 ) == NOT_FOUND );
}

// END UTILITY FUNCTIONS ====================================================

////
// Tries to find the path to the db-file and stores it in 'path'
// Returns TRUE if found, else FALSE
int find_db(char* path) {
    char ext[] = "\\users\\all users\\comodo\\firewall pro\\cislogs.sdb";
    char *var, *drive;

    var = getenv(ENV_VAR);    // If user has set the db location and
    if(var){                  // the file exists, use it.
        if( readable(var) ) {
            strcpy(path,var);
            return TRUE;
        } else {
            error("Environment variable " ENV_VAR " points to a location that isn't readable: %s", var);
        }
    }

    drive = getenv("SystemDrive");  // Try to find the db using standard
    if( !drive ) {                  // installation directories
        drive = "C:";
    }
    strcpy(path,drive);
    strcat(path,ext);
    return readable(path);
}

void convert_to_ip(char* dst, const unsigned char* src){
    // Comodo stores the IP as two 32bit integers. The second is what we want, 
    // the first I have no clue what it represents (ipv6 address perhaps..)
    sprintf(dst, "%d.%d.%d.%d\0", src[4],src[5],src[6],src[7]);
}

BOOL sig_handler(DWORD signal) {
    switch(signal) {
        case CTRL_C_EVENT:
        case CTRL_CLOSE_EVENT:
        case CTRL_LOGOFF_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            terminate(0);
            break;
        default: ;// Do nothing;
    }
    return FALSE;
}

void trap_signals() {
    // http://msdn.microsoft.com/en-us/library/ms685049%28VS.85%29.aspx
    if(! SetConsoleCtrlHandler( (PHANDLER_ROUTINE) sig_handler, TRUE ) );
}

void populate_result(sqlite3_stmt* stmt, int cols, resultrow* row) {
    int protocol,direction,action, col=0;
    long slen;
    const unsigned char *srcaddr, *dstaddr;
    static char dst_ip[16];
    static char src_ip[16];

    // id,datetime(logdate),path,pid,protocol,direction,srcport,dstport,action,srcaddr,dstaddr

    row->id        = sqlite3_column_int(stmt,col++);
    row->logdate   = sqlite3_column_text(stmt,col++);
    row->path      = sqlite3_column_text(stmt,col++);
    row->pid       = sqlite3_column_int(stmt,col++);
    protocol       = sqlite3_column_int(stmt,col++);
    direction      = sqlite3_column_int(stmt,col++);
    row->srcport   = sqlite3_column_int(stmt,col++);
    row->dstport   = sqlite3_column_int(stmt,col++);
    action         = sqlite3_column_int(stmt,col++);

    srcaddr        = sqlite3_column_blob(stmt,col);
    dstaddr        = sqlite3_column_blob(stmt,col);

    switch(protocol){
        case  2: row->protocol = "IGMP"; break;
        case  6: row->protocol = "TCP" ; break;
        case 17: row->protocol = "UDP" ; break;
        default: row->protocol = "?"   ; break;
    }
    switch(direction){
        case  1:  row->direction = "OUT" ; break;
        default:  row->direction = "IN"  ; break;
    }
    switch(action){
        case  2:  row->action = "Blocked" ; break;
        case  8:  row->action = "Asked"   ; break;
        default:  row->action = "?"       ; break;
    }
    convert_to_ip(dst_ip, dstaddr);
    convert_to_ip(src_ip, srcaddr);
    row->dstaddr = dst_ip;
    row->srcaddr = src_ip;
}

void execute_query(char* sql, int bind_value, void (*callback)(resultrow*) ) {
    sqlite3_stmt* stmt;
    int cols, rc = 0;
    resultrow row;

    if(opts.db == 0) {
        if( sqlite3_open_v2(opts.db_file, &opts.db, SQLITE_OPEN_READONLY, 0) != SQLITE_OK ) {
            printf("Failed to open SQLite3 database %d", opts.db_file);
        }
        if(opts.verbose) printf("Opening DB connection\n");
    }
    if(opts.verbose) printf("Preparing statement\n");
    if( sqlite3_prepare_v2(opts.db, sql, -1, &stmt, 0) != SQLITE_OK ) {
        error("Failed to prepare statement: %s", sql);
    }
    if( bind_value > 0 && sqlite3_bind_int(stmt, 1, bind_value) != SQLITE_OK) {
        error("Failed to sql-bind value: %d for sql: %s", bind_value, sql);
    }
    cols = sqlite3_column_count(stmt);
    if(opts.verbose) printf("Processing rows\n");
    rc = sqlite3_step(stmt);
    while(rc == SQLITE_ROW) {
        opts._last_row_id = sqlite3_column_int(stmt,0);
        populate_result(stmt,cols,&row);
        callback(&row);

        rc = sqlite3_step(stmt);
    }
    if(opts.verbose) printf("Recycling statement\n");
    sqlite3_finalize(stmt);
}

void print_row(resultrow* row) {
    printf("%s %-7s %-3s %-4s %15s %-5d -> %15s %-5d %5d %s\n",
        row->logdate,
        row->action,
        row->direction,
        row->protocol,
        row->srcaddr,
        row->srcport,
        row->dstaddr,
        row->dstport,
        row->pid,
        row->path
    );
}

void tail(){
    switch(opts.cmd) {

        case FOLLOW:
            while(TRUE) {
                if (opts._last_row_id >= 0) {
                    execute_query("SELECT " SELECT_FIELDS " from fwevents WHERE id > ? ORDER BY ID ASC", opts._last_row_id , print_row);
                } else {
                    execute_query("SELECT * FROM (SELECT " SELECT_FIELDS " from fwevents ORDER BY ID DESC LIMIT ?) ORDER BY ID ASC", opts.c_recs , print_row);
                }
                Sleep(opts.sleep);
            }
            break;

        case LAST_N:
            execute_query("SELECT * FROM (SELECT " SELECT_FIELDS " from fwevents ORDER BY ID DESC LIMIT ?) ORDER BY ID ASC", opts.c_recs , print_row);
            break;

        case ALL:
            execute_query("SELECT " SELECT_FIELDS " from fwevents ORDER BY ID ASC", 0 , print_row);
            break;

        default:       // Should never get here, but if we do then just exit
            error("Bug found! Internal command received: %d. Please notify the author about this.", opts.cmd);
    }
}

void usage() {
    printf("usage: tail-comodo [OPTION]\n\n"
           "Tails the Comodo Firewall event log\n\n"
           "Options:\n"
           "  -a    Show all firewall events\n"
           "  -f    Follow the log, displaying events as they occur\n"
           "  -h    Display this help\n"
           "  -N    Show the last N event, where N is positive number\n"
           "  -s N  Sleep interval between log polling. Default is 1 second.\n"
           "  -v    Verbose, print some internal info during execution\n"
           "  -V    Show the version of the program\n\n"
           "Note: The environment variable " ENV_VAR " overrides the default location\n"
           "      for the database file to use.\n");
    exit(1);
}

int main(int argc, char* argv[]) {
    int i;
    char* arg;
    char db_file[512];

    // Setup default configuration for the execution
    opts.cmd     = LAST_N;
    opts.c_recs  = 10;
    opts.sleep   = 1 * 1000;
    opts.verbose = FALSE;
    opts.db_file = db_file;
    opts.db      = 0;
    opts._last_row_id = -1;

    trap_signals();

    if(! find_db(db_file) )
        error("Failed to find cislogs.sdb, set the " ENV_VAR 
              " environment variable to the location to the file");
    
    // Command line parsing
    for(i=1; i<argc; i++){
        arg = argv[i];

        if( arg[0] == '-' ) {
            arg++;

            if( strlen(arg) == 0 ) {
                continue;

            } else if( arg[0] == 'h' || arg[0] == '?' ) {
                usage();

            } else if( isdigits(arg) ) {
                opts.c_recs = atoi(arg);

            } else if( strcmp("f",arg)==0 ) {
                opts.cmd = FOLLOW;

            } else if( strcmp("a",arg)==0 ) {
                opts.cmd = ALL;

            } else if( strcmp("v",arg)==0 ) {
                opts.verbose = TRUE;

            } else if( strcmp("V",arg)==0 ) {
                printf("Version: " VERSION "\n");
                terminate(0);

            } else if( strcmp("s",arg)==0 ) {
                if( i+1 < argc) {
                    arg = argv[++i];
                    if( !isdigits(arg) ) {
                        error("sleep interval must be numeric");
                    }
                    opts.sleep = atoi(arg) * 1000;
                    if( opts.sleep <= 0 ) {
                        error("sleep interval must be larger than zero");
                    }
                } else {
                    error("Option \"-s N\" must have number of seconds as an argument");
                }
            } else {
                error("Invalid option: %s", argv[i]);
            }
        } else {
            error("Invalid argument: %s", argv[i]);
        }

    } // END command line parsing

    if(opts.verbose) {
        printf("Using firewall db file: %s\n\n", opts.db_file);
    }
    tail();
    terminate(0);
}
