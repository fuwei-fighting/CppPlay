//
// Created by fuwei on 11/26/24.
//

#include "prochandler.h"

using namespace UnixUtils;

constexpr int kBufSize = 1024;

void ProcHandler::getPidByName(pid_t* pid, char* taskName) {
    DIR* procDir;
    struct dirent* ptr;
    FILE* fp;
    char filePath[50];
    char curTaskName[50];

    char buffer[kBufSize];

    procDir = opendir("/proc");
    if (NULL != procDir) {
        while ((ptr = readdir(procDir)) != NULL) {
            // 循环读取/proc下的每一个文件&文件夹

            if ((strcmp(ptr->d_name, ".") == 0) || (strcmp(ptr->d_name, "..") == 0)) {
                // 如果读取到的是"."或者".."则跳过
                continue;
            }
            if (DT_DIR != ptr->d_type) {
                // 读取到的不是文件夹名字也跳过
                continue;
            }
            sprintf(filePath, "/proc/%s/status", ptr->d_name);  // ptr->d_name表示遍历到的进程号

            //            printf(" ptr->d_name = %s, filePath = %s.\n", ptr->d_name, filePath);
            fp = fopen(filePath, "r");
            if (NULL != fp) {
                if (fgets(buffer, kBufSize - 1, fp) == NULL) {
                    fclose(fp);
                    continue;
                }
                sscanf(buffer, "%s %s", curTaskName);
                // 如果文件内容满足要求则打印路径的名字（即进程的PID）
                if (!strcmp(taskName, curTaskName)) {
                    sscanf(ptr->d_name, "%d", pid);
                }
                fclose(fp);
            }
        }
        closedir(procDir);
    }
}

/**
 * 根据pid进程号获取进程名
 * @param pid
 * @param taskName
 */
void ProcHandler::getNameByPid(pid_t pid, char* taskName) {
    char procPidPath[kBufSize];
    char buffer[PATH_MAX];

    sprintf(procPidPath, "/proc/%d/status", pid);
    printf("procPidPath = %s.\n", procPidPath);
    FILE* fp = fopen(procPidPath, "r");

    if (NULL != fp) {
        if (fgets(buffer, PATH_MAX - 1, fp) == NULL) {
            fclose(fp);
            return;
        }
        sscanf(buffer, "%s %s", taskName);
        printf("getNameByPid taskName = %s.\n", taskName);
        fclose(fp);
    }
}
