HASH=-$(cd $DIR && git rev-parse --verify HEAD 2> /dev/null || echo nohash)
