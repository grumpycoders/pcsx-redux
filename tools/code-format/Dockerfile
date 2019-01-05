FROM ubuntu:18.04 AS build

RUN apt-get -y update
RUN apt-get -y install apt-utils
RUN apt-get -y dist-upgrade
RUN apt-get -y install build-essential
COPY tabremover.c .
RUN gcc -o /bin/tabremover -O3 tabremover.c

FROM ubuntu:18.04 AS run

RUN apt-get -y update
RUN apt-get -y install apt-utils
RUN apt-get -y dist-upgrade
RUN apt-get -y install clang-format tofrodos
COPY --from=build /bin/tabremover /bin
COPY run-format.sh .

CMD ["/run-format.sh"]
