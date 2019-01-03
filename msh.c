/*

	Name:	Indra Bhurtel
	ID:	1001542825

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>

#define MAX_CMD_LENGTH 	100
#define MAX_HISTORY 	15
#define MAX_PID_LOG		15
#define MAX_ARGUMENTS	11
#define PATH_DIR 		"PATH=.:/usr/local/bin:/usr/bin:/bin"

/// assignment shows index for history should between 1 and 15 in text and shows start with 0 in
/// image so this below listed controls the index start if 0 or 1
#define LIST_START_INDEX 1

/// argument_container is a fixed allocated container for arguments
/// but execvp needs NULL terminated argument vector list
/// so arguments will point to containers with last elemtent NULL.
char argument_container[MAX_ARGUMENTS][MAX_CMD_LENGTH] = {{ 0} };
char *arguments[MAX_ARGUMENTS + 1]; // +1 is for last NULL

/// history is a circuler buffer to log command history
/// hist_index will always point to next available container
/// it will always overwrite the old entries if full.
char history[MAX_HISTORY][MAX_CMD_LENGTH] = {{ 0 }};
int hist_index = 0;

/// pids_log is circuler buffer to hold pid history
/// pids_index will point to next available container
/// it will always overwrite the old entries if full.
int pids_log[MAX_PID_LOG] = { 0 };
int pids_index = 0;

/// skip is used for Ctrl-Z interrupt to avoid
/// blocking read call to continue with `bg`.
int skip = 0;

void print_error(char *msg);
void insert_pid_log(int pid);
int get_last_pid();
void print_pid_log();
void insert_history_log(char* str);
char* get_cmd(int i);
void print_history();
int execute_history();
void sigHandler(int signum);


/// set PATH variable to search directory to
/// .:/usr/local/bin:/usr/bin:/bin
void init_env() {
	putenv(PATH_DIR);
}

/// attach SIGINT(ctrl-c), SIGTSTP(Ctrl-Z) and SIGCHLD to custom handler
/// instead of default one to control behaviour
void init_signals() {
	signal(SIGINT, sigHandler);
	signal(SIGTSTP, sigHandler);
	signal(SIGCHLD, sigHandler);
}

/// our custom signal handler
/// params:
///		signum : Signal number
void sigHandler(int signum){
	int status;

	/// get the last child process pid
	int pid = get_last_pid();
    switch(signum){
     	case SIGTSTP:
     		// if last process pid is not zero then Ctrl-Z it
     		if (pid) kill(pid, SIGTSTP);
     		skip = 1;
     		break;
     	case SIGINT:
     		// if last process pid is not zero then Ctrl-C it
     		if (pid) kill(pid, SIGINT);
     		break;
        case SIGCHLD:
            // note that the last argument is important for the wait to work
            waitpid(-1, &status, WNOHANG);
            break;
     }
}

/// this send the process PID a SIGCONT signal to continue
/// after SIGTSTP(Ctrl-Z) used in bg command
/// params:
///		pid : pid of process to continue
void send_process_to_background(int pid) {
	kill(pid, SIGCONT);
}


/// it tokenizes the input `buffer` to arguments inf argument_container
/// also sets te arguments vector point to correct container and sets
/// last element of arguments array to NULL.
/// params:
///		cmd : null terminated string of command with arguments
/// return
///		int: total number of arguments found including command name
int parse_arguments(char* cmd) {
	// getrid of newline as it is not required
	char* nl = strchr(cmd, '\n');
	if (nl) *nl = 0;

	char *tok = strtok(cmd, " ");
	int index = 0;
	while(tok != NULL) {
		strcpy(argument_container[index], tok);
		arguments[index] = argument_container[index];
		tok = strtok(NULL, " ");
		index++;
	}
	arguments[index] = NULL;
	return index;
}

/// reading output of some command like `ls` throught pipe contains newline charaters
/// this cleans the output to make it more readable
/// for other commands it just print normal output read via pipe
/// params:
///		buffer: null terminated char array.
void print_pipe_buffer(char* buffer) {
	if (strcmp(arguments[0], "ls") != 0) {
		printf("%s", buffer);
	}
	else {
		int i=0;
		while(buffer[i] != 0) {
			printf("%c", buffer[i] == '\n' ? ' ' : buffer[i]);
			i++;
		}
	}
	if (strlen(buffer) > 0) printf("\n");
}


/// this funtion executes command stored in argument[0] with param vector argument
/// it is mendatory to set argument vector before calling this function using parse_arguments
/// this also uses pause instead of wait to handle signal such as Ctrl-Z
void execute() {
	/// pipe to read child command out and printing it to parent stdout
	int link_child_to_host[2];

	/// buffer to read pipe child output
	char buffer[4096] = {0};

	if (pipe(link_child_to_host) == -1) {
		print_error("pipe creation error");
		return;
	}

	int pid = fork();
	if (pid == -1) {
		print_error("execute fork error");
	}
	else if (pid == 0) {
		/// if pid 0, then it is a child process
		/// create duplicate of pipe and attach it to child stdout
		while ((dup2(link_child_to_host[1], STDOUT_FILENO) == -1) && (errno == EINTR)) {}
		close(link_child_to_host[1]);
		close(link_child_to_host[0]);
		if (execvp(arguments[0], arguments) == -1) {
			if (errno == ENOENT) {
				printf("%s: Command not found.\n", arguments[0]);
			}
			exit(0);
		}
	}
	else {
		/// this is parent process
		/// save the child pid
		insert_pid_log(pid);

		/// close pipe child side link
		close(link_child_to_host[1]);

		/// wait for process to compelete
		/// for short commands it will close soon and will generate SIGCHLD
		/// for blocking process we will wait for SIGCHLD or SIGTSTP(Ctrl-Z)
		pause();

		/// in case of SIGTSTP we skip the reading of pipe
		if (!skip) {
			int bytes = read(link_child_to_host[0], buffer, sizeof(buffer));
			if(bytes > 0) print_pipe_buffer(buffer);
		}
	}
}

int main() {
	char buffer[MAX_CMD_LENGTH];
	int args;
	int ok_to_execute;

	init_env();
	init_signals();

	while(1) {
		printf("msh> ");
		if (fgets(buffer, MAX_CMD_LENGTH, stdin) != NULL) {

			args = parse_arguments(buffer);
			if (args > 0) {
				/// ok_to_execute is used to mark if argument buffer is valid or not
				/// and exec is called using that buffer
				ok_to_execute = 1;

				/// this is used to mark if pipe from child to parent should be skipped to read
				/// or not.
				/// read is skipped in case of Ctrl-Z.
				skip = 0;
				if(strcmp(arguments[0], "exit") == 0)  break;
				else if(strcmp(arguments[0], "quit") == 0)  break;
				else if (strcmp(arguments[0], "history") == 0) {
					print_history();
					ok_to_execute = 0;
				}
				else if (strcmp(arguments[0], "listpids") == 0) {
					print_pid_log();
					ok_to_execute = 0;
				}
				else if (strcmp(arguments[0], "cd") == 0) {
					insert_history_log(buffer);
					if (chdir(arguments[1]) == -1)
						print_error("change dir error");
					ok_to_execute = 0;
				}
				else if (strcmp(arguments[0], "bg") == 0) {
					ok_to_execute = 0;
					send_process_to_background(get_last_pid());
				}
				else if(arguments[0][0] == '!') ok_to_execute = execute_history();
				else insert_history_log(buffer);

				if (ok_to_execute)
					execute();
			}
		}
	}
	return 0;
}

/// used to print errno message with passed msg
/// params:
///		msg: null terminated message to include with error
void print_error(char *msg) {
	printf("%s, %s\n", msg, strerror(errno));
}

///***************** pid logging related function START ***********************///

/// save pid to logs
/// params:
///		pid : int, pid to save
void insert_pid_log(int pid) {
	pids_log[pids_index] = pid;
	pids_index = (pids_index+1)%MAX_PID_LOG;
}

/// get last active pid
/// return
///		int : get last active or completed(never mind) pid
int get_last_pid() {
	int index = pids_index == 0 ? MAX_PID_LOG:pids_index;
	index--;
	return pids_log[index];
}

void print_pid_log() {
	int index = pids_index;
	int count = 0;

	/// we only have one index so we rotate whole buffer to get to the start
	/// and here == 0 is used to check for empty spots
	/// once it is filled we do not have to worry about this as whole buffer
	/// is filled and next to current is start index.
	while(pids_log[index] == 0) {
		index = (index+1)%MAX_PID_LOG;
		count++;
		if (count > MAX_PID_LOG) return;
	}

	/// start index in assignment text is 1 and in ref image it is 0
	/// so macro LIST_START_INDEX is used to control it.
	count = LIST_START_INDEX;
	while(1) {
		printf("%d: %d\n", count++, pids_log[index]);
		index = (index+1)%MAX_PID_LOG;
		if (index == pids_index) break;
	}
}

///***************** History logging related function START ***********************///

/// save the whole string with params in logs
/// params:
/// 	str: null terminated complete string from stdin
void insert_history_log(char* str) {
	strcpy(history[hist_index], str);
	hist_index = (hist_index+1)%MAX_HISTORY;
}

/// get the index command string
/// params:
///		i : int index to get the command string from buffer
/// return:
///		char* : char refrence in history log, complete command string
///		WARNING: try not to write the returned char array, it will corrupt the stored
///				 log for that entry may generate segfault
char* get_cmd(int i) {

	/// start index in assignment text is 1 and in ref image it is 0
	/// so macro LIST_START_INDEX is used to control it.
	if (i > (MAX_HISTORY + LIST_START_INDEX)) return NULL;
	if (i < LIST_START_INDEX) return  NULL;

	/// we only have one index so we rotate whole buffer to get to the start
	/// and here == 0 is used to check for empty spots
	/// once it is filled we do not have to worry about this as whole buffer
	/// is filled and next to current is start index.
	int count = 0;
	int index = hist_index;
	while(history[index][0] == 0) {
		index = (index+1)%MAX_HISTORY;
		count++;
		if (count > MAX_HISTORY) return NULL;
	}

	/// start index in assignment text is 1 and in ref image it is 0
	/// so macro LIST_START_INDEX is used to control it.
	i -= LIST_START_INDEX;
	while(i > 0) {
		index = (index+1)%MAX_HISTORY;
		i--;
	}
	return history[index];
}

void print_history() {
	/// we only have one index so we rotate whole buffer to get to the start
	/// and here == 0 is used to check for empty spots
	/// once it is filled we do not have to worry about this as whole buffer
	/// is filled and next to current is start index.
	int index = hist_index;
	int count = 0;
	while(history[index][0] == 0) {
		index = (index+1)%MAX_HISTORY;
		count++;
		if (count > MAX_HISTORY) return;
	}

	/// start index in assignment text is 1 and in ref image it is 0
	/// so macro LIST_START_INDEX is used to control it.
	count = LIST_START_INDEX;
	while(1) {
		printf("%d: %s\n", count++, history[index]);
		index = (index+1)%MAX_HISTORY;
		if (index == hist_index) break;
	}
}

/// this function will fetch proper command string from history logs
/// parse it and return 1 if succefull or 0 if something went wrong
/// return:
/// 	int : 1 if success or 0 for failure
int execute_history() {
	char *endptr;
	int cmd = strtol(&arguments[0][1], &endptr, 10);
	if (cmd == 0) {
		if (errno == EINVAL || errno == ERANGE) {
			printf("Wrong history command\n");
			return 0;
		}
	}

	/// get the stored command in history
	/// for invalid index it will return NULL
	char *buffer = get_cmd(cmd);
	if (buffer == NULL) {
		printf("history command index out of range\n");
		return 0;
	}

	/// for valid index but empty spot in history it will return
	/// empty string(allocated as first element zero)
	if (buffer[0] == 0) {
		printf("Command not in history\n");
		return 0;
	}

	/// parse the stored command and set arguments
	parse_arguments(buffer);
	return 1;
}
