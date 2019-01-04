#!/bin/bash
BASEPATH=$(cd `dirname $0`; pwd)
echo $BASEPATH
cd $BASEPATH
LIBPATH=$BASEPATH/../lib/
CONFPATH=$BASEPATH/../conf/

CLASSPATH=""

for file in $(ls $LIBPATH)
do
CLASSPATH="$CLASSPATH$LIBPATH$file:"
done

CLASSPATH=$CLASSPATH$BASEPATH:$CONFPATH

nohup java -cp $CLASSPATH cn.edu.jslab6.autoresponse.forensictask.AutoResponseMain > ../logs/sys.log 2>&1 &
