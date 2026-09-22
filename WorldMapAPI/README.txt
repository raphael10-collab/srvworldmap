(base) root@WorldMap:/srv/worldmap/WorldMapAPI# rm -rf builddir/

(base) root@WorldMap:/srv/worldmap/WorldMapAPI# cmake -S . -B builddir -DCMAKE_BUILD_TYPE=Release

(base) root@WorldMap:/srv/worldmap/WorldMapAPI# cmake --build builddir \
    --clean-first \
    --parallel "$(nproc)"

(base) root@WorldMap:/srv/worldmap/WorldMapAPI# sudo pkill -f WorldMapAPI || true

(base) root@WorldMap:/srv/worldmap/WorldMapAPI# ./builddir/WorldMapAPI
