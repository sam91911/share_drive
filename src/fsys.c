#include "fsys.h"

int fsys_init(){
	struct stat oper_stat;
	int oper_fd;
	FILE* oper_file;
	if(access("fsys", F_OK)){
		if(errno == ENOENT){
			if(mkdir("fsys", 0744)){
				return -1;
			}
		}else{
			return -1;
		}
	}
	if(stat("fsys", &oper_stat)){
		return -1;
	}
	if(!(S_IFDIR&(oper_stat.st_mode))){
		return -1;
	}
	return 0;
}

int fsys_check(uint64_t id, char* name){
	struct stat oper_stat;
	int oper_fd;
	FILE* oper_file;
	char oper_str[512];
	if(access("fsys", F_OK)){
		return -1;
	}
	if(stat("fsys", &oper_stat)){
		return -1;
	}
	if(!(S_IFDIR&(oper_stat.st_mode))){
		return -1;
	}
	if(sprintf(oper_str, "fsys/%016lX", id) < 1) return -1;
	if(access(oper_str, F_OK)){
		return -1;
	}
	if(stat(oper_str, &oper_stat)){
		return -1;
	}
	if(!(S_IFDIR&(oper_stat.st_mode))){
		return -1;
	}
	if(!name) return 0;
	if(sprintf(oper_str, "fsys/%016lX/%s", id, name) < 1) return -1;
	if(access(oper_str, F_OK|R_OK)){
		return -1;
	}
	return 0;
}

uint64_t fsys_size(uint64_t id, char* name){
	struct stat oper_stat;
	char oper_str[512];
	if(!name) return 0;
	if(fsys_check(id, name)) return 0;
	if(sprintf(oper_str, "fsys/%016lX/%s", id, name) < 1) return 0;
	if(stat(oper_str, &oper_stat)){
		return 0;
	}
	return oper_stat.st_size;
}

int fsys_store(uint64_t id, char* name){
	struct stat oper_stat;
	int oper_fd;
	FILE* oper_file;
	char oper_str[512];
	if(!name) return -1;
	if(sprintf(oper_str, "fsys/%016lX", id) < 1) return -1;
	if(access(oper_str, F_OK)){
		if(errno == ENOENT){
			if(mkdir(oper_str, 0744)){
				return -1;
			}
		}else{
			return -1;
		}
	}
	if(stat(oper_str, &oper_stat)){
		return -1;
	}
	if(!(S_IFDIR&(oper_stat.st_mode))){
		return -1;
	}
	if(sprintf(oper_str, "fsys/%016lX/%s", id, name) < 1) return -1;
	if(!fsys_check(id, name)){
		oper_fd = open(oper_str, O_WRONLY);
		return oper_fd;
	}else{
		oper_fd = open(oper_str, O_WRONLY|O_CREAT, 0644);
		return oper_fd;
	}
}

int fsys_get(uint64_t id, char* name){
	struct stat oper_stat;
	int oper_fd;
	FILE* oper_file;
	char oper_str[512];
	int64_t read_bytes;
	if(!name) return -1;
	if(fsys_check(id, name)) return -1;
	if(sprintf(oper_str, "fsys/%016lX/%s", id, name) < 1) return -1;
	oper_fd = open(oper_str, O_RDONLY);
	return oper_fd;
}

int fsys_del(uint64_t id, char* name){
	if(fsys_check(id, name)) return 0;
	char oper_str[512];
	if(sprintf(oper_str, "fsys/%016lX/%s", id, name) < 1) return -1;
	if(remove(oper_str)) return -1;
	return 0;
}
