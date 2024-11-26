//
// Created by fuwei on 11/26/24.
//

#ifndef IMAGEVIEW_PROCHANDLER_H
#define IMAGEVIEW_PROCHANDLER_H

#include <sys/types.h>

#include <dirent.h>
#include <stdio.h>
#include <string.h>

namespace UnixUtils {

class ProcHandler {
   public:
    static void getPidByName(pid_t* pid, char* taskName);
    static void getNameByPid(pid_t pid, char* taskName);
};

}  // namespace UnixUtils

#endif  // IMAGEVIEW_PROCHANDLER_H
