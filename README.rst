tun2socks
===============


`tun2socks` 里面的 `socks` 指 `ss-remote`.


Try
--------


.. code:: bash

    ssserver -k "" -m "none" -s "127.0.0.1:9000"

    cd tun2socks
    
    # NOTE: 手动在 src/main.rs 里面把  ss-remote 的地址配置上去。
    cargo build --release; sudo target/release/tun2socks
