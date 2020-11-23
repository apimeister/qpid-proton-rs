DYLD_LIBRARY_PATH=/usr/local/Cellar/qpid-proton/0.33.0


run qpid server

docker run -it --rm -p 8080:8080 -p 5672:5672 -e AUTH=admin:admin itherz/qpid-server