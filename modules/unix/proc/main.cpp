//
// Created by fuwei on 11/26/24.
//
#include <unistd.h>
#include "prochandler.h"

int main(int argc, char* argv[]) {
    char taskName[100];
    pid_t pid = getpid();

    printf("pid of this process:%d\n", pid);

    UnixUtils::ProcHandler::getNameByPid(pid, taskName);

    strcpy(taskName, argv[0]);
    printf("task name:%s\n", taskName);
    UnixUtils::ProcHandler::getPidByName(&pid, taskName);
    printf("getNameByPid:%s\n", taskName);

    UnixUtils::ProcHandler::getPidByName(&pid, taskName);

    printf("getPidByName:%d\n", pid);
    sleep(15);
}