FROM ubuntu:20.04 AS build

# The tzdata package isn't docker-friendly, and something pulls it.
ENV DEBIAN_FRONTEND noninteractive
ENV TZ Etc/GMT

RUN apt-get -y update
RUN apt-get -y install apt-utils
RUN apt-get -y dist-upgrade
RUN apt-get -y install build-essential
RUN apt-get -y install wget
RUN apt-get -y install cmake
RUN apt-get -y install git
COPY tabremover.c .
RUN gcc -o /bin/tabremover -O3 tabremover.c
RUN git clone --recursive https://github.com/Koihik/LuaFormatter.git
WORKDIR LuaFormatter
RUN cmake .
RUN make lua-format

FROM ubuntu:20.04 AS run

RUN apt-get -y update
RUN apt-get -y install apt-utils
RUN apt-get -y dist-upgrade
RUN apt-get -y install clang-format tofrodos
COPY --from=build /bin/tabremover /bin
COPY --from=build /LuaFormatter/lua-format /bin
COPY run-format.sh .
COPY lua-format.config .

CMD ["/run-format.sh"]
