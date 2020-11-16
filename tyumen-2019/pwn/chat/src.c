#include "stdlib.h"
#include "stdio.h"
#include "string.h"
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>

const int MAX_USER_CNT = 10000;

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_RESET   "\x1b[0m"
#define ANSI_LINE_ABOVE   "\x1b[1A"
static void cleanup(void) __attribute__ ((destructor));

struct user{
    char token[10];
    char nick[10];
    int isAdmin; 
};


struct msg{
    char msg[128];
    int time_created;
    int chat_id;
    char meta_inf[36];
};

char *dict_for_kisa[10];
int cnt_prase = 0;

void print_lines(char *lines[]){
    printf("Users:\n");
    for (int i = 0; strcmp(lines[i], ""); i++){
        printf("\t%s\n", lines[i]);
    }
}

void log_err(char *err){
    printf(ANSI_COLOR_RED "ERROR: " ANSI_COLOR_RESET);
    printf(err);
    printf("\n");
}

int read_lines(char *file, char *lines[]){
    int f;
    if ((f = open(file, O_RDONLY)) != -1){
        char *parse;
        int cnt_lines = 1;
        struct stat st;
        fstat(f, &st);
        parse = malloc(st.st_size);
        read(f, parse, st.st_size);

        lines[0] = parse;
        for(int i = 0; parse[i]; i++){
            if(parse[i] == '\n'){
                parse[i++] = '\0';
                lines[cnt_lines++] = (parse + i);
            }
        }
        lines[cnt_lines] = "";
        return cnt_lines;
    } else {
        return -1;
    }
}

void print_flag0(char *token){
    char path[24] = "flags/flag0/";
    strcat(path, token);
    char *tokens[1];
    int cnt = read_lines(path, tokens);
    if (cnt == -1){
        printf("Not this task (token)");
        return;
    }
    printf("%s\n", tokens[0]);
    free(tokens[0]);
}

void change_info(char *info, char* token){
    char path[24] = "flags/flag1/";
    strcat(path, token);
    char *tokens[1];
    int cnt = read_lines(path, tokens);
    if (cnt == -1){
        return;
    }
    strcpy(info, tokens[0]);
    free(tokens[0]);
}

void flag2(char *token, char *dst){
    char path[24] = "flags/flag2/";
    strcat(path, token);
    char *tokens[1];
    int cnt = read_lines(path, tokens);
    if (cnt == -1){
        strcpy(dst, "Flag_Not_this_token");
        return;
    }
    strcpy(dst, tokens[0]);
    free(tokens[0]);
}

void print_user(struct user *user){
    printf("User info:\n");
    printf("   Nick: \t%s\n", user->nick);
    printf("   His token:\t%s\n", user->token);
    printf("   isAdmin: \t%d\n", user->isAdmin);
    if (user->isAdmin == 1){
        print_flag0(user->token);
    } 
}

struct user* create_user(char *nick, char* token){
    struct user *user = malloc(sizeof(user));
    user->isAdmin = 0;
    strcpy(user->token, token);
    strcpy(user->nick, nick);
    return user;
}

void fill_dict(){
    int cnt_lines = read_lines("./dict.txt", dict_for_kisa);
    if (cnt_lines == -1) {
        log_err("Sorry, dictionary for KISA is not found. Contact the admin");
        return;
    }
    cnt_prase = cnt_lines;
}

// TODO: make it smarter
char *guess_answer(char *message){
    return dict_for_kisa[rand() % cnt_prase];
}

char* timestamp_str(time_t t){
    return ctime(&t) + 11;
}

void tell_kisa(char *message){
    char* msg = guess_answer(message);
    printf(ANSI_COLOR_MAGENTA "[%8.8s] <КИСА>: %s\n" ANSI_COLOR_RESET, 
        timestamp_str(time(NULL)),
        msg);
}

void chat_kisa(char *message, struct user* user){
    struct msg msg;
    strcpy(msg.msg, message);
    msg.time_created = time(NULL);
    flag2(user->token, msg.meta_inf);
    printf(ANSI_LINE_ABOVE "[%8.8s] %s: %s\n", 
        timestamp_str(msg.time_created), user->nick, msg.msg);
    tell_kisa(msg.msg);
}

void new_phrase(){
    char phrase[256];
    printf("Input new phrase for KISA: ");
    scanf("%255s", phrase);
    while(getchar() != '\n');  
    // TODO: Append it to the file dict.txt
}

void start_chat(struct user *user){
    char message[128];
    char *err = malloc(sizeof(char)*148);
    printf("Connecting to chat.");
    for (int i = 0; i < 3; i++){
        // sleep(1);
        printf(".");
    }
    printf(".\n");
    printf("To quite chat enter '\\q'\n");
    printf("\n");
    tell_kisa("Привет! Познакомимся?");
    
    while (1){
        printf("%s: ", user->nick);
        scanf("%128[^\n]", message);
        while(getchar() != '\n');  
        if (message[0] == '\\') {
            switch (message[1])
            {
                case 'q':
                    return;
                    break;
                case 'n':
                    new_phrase();
                    break;
                default:
                    strcpy(err, "cmd is invalid: ");
                    log_err(strcat(err, message));
                    break;
            }
        } else {
            chat_kisa(message, user);
        }
    }
}

void main_menu(struct user *user){
    int c = 1;
    int choice = 0;
    while (c){
        printf("\n");
        printf("Select command:\n");
        printf("    1) Join chat\n");
        printf("    2) See user information\n");
        printf("    3) Quit\n\n");
        
        printf(">> ");
        scanf("%d", &choice);
        while(getchar() != '\n');  
        printf("\n\n");

        switch (choice){
            case 1: start_chat(user); break;
            case 2: print_user(user); break;
            case 3: c = 0; break;
            default: printf("Please, select number from 1 to 3\n"); break;
        }
        choice = 0;
    }
}

int find_user(char *users[], char *user){
    int i;
    for (i = 0; strcmp(users[i], user) && strcmp(users[i], ""); i++){}
    return i;
}

int find_token(char *token){
    int f;
    char *users[MAX_USER_CNT];
    int user_cnt = read_lines("./users.txt", users);
    if (user_cnt == -1) {
        log_err("Users token file is not found");
        log_err("Contact the admin");
        return -1;
    }

    int user_id;
    if ((user_id = find_user(users, token)) != user_cnt){
        return user_id;
    }

    printf("Cur user_id: %d\n", user_id);
    free (users[0]);
    return -1;
}

void welcome(char *some_info){
    char token[10];
    char nick[12] = "";
    int user_id;
    printf("Hello, guest!\n");
    printf("Enter your token: ");
    scanf("%9s", token);

    if ((user_id = find_token(token)) == -1){
        log_err("There is no such user");
        return;
    }
    change_info(some_info, token);

    printf("Enter your nick: ");
    scanf("%11s", nick);

    struct user *user = create_user(nick, token);

    printf("\n");
    printf("Welcome to our chat!\n");
    main_menu(user);
}

int main(int argc, char* argv[]){
    setvbuf(stdout, NULL, _IONBF, 0);
    srand(time(NULL));
    fill_dict();
    welcome(argv[1]);
    printf("Good bye!\n");
    free(dict_for_kisa[0]);
    return 0;
}

void cleanup(void){
    free(dict_for_kisa[0]);
}
