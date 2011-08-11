#!/bin/bash
#===============================================================================
#
#          FILE:  auto.sh
# 
#         USAGE:  ./auto.sh 
# 
#   DESCRIPTION:  auto build
# 
#       OPTIONS:  ---
#  REQUIREMENTS:  ---
#          BUGS:  ---
#         NOTES:  ---
#        AUTHOR:  Ning.Zhang (zhn), ning DOT zhang AT Archermind DOT com
#       COMPANY:  Archermind Technology (Nanjing) Co., Ltd. 
#       VERSION:  1.0
#       CREATED:  08/11/2011 05:38:35 AM GMT
#      REVISION:  ---
#===============================================================================

autoheader
autoreconf --install
./configure $@
make
