WireGuard 转换 nekoray 节点链接，只需要一个 wg-config.conf 配置文件，再输入一个IP和Port端口，即可生成 nekoray 节点的链接。本程序使用 loop 死循环，可以继续生成nekoray节点的链接，想要退出程序，把黑色窗口关闭即可。

【新增加一个程序】支持批量生成nekoray节点的链接，将优选的IP或server:port放到 ip.txt 文件中，运行程序，生成的节点链接输出到 output.txt 文件中。

### 1、软件效果截图

<img src="images\screenshot1.png" />

<img src="images\screenshot2.png" />

### 2、使用到的工具

NekoBox Windows版：https://github.com/MatsuriDayo/nekoray/releases

### 3、温馨提示

WireGuard中的MTU值，修改不同的值，可能有一定几率提升网速，甚至，由原来能正常上网的，后来被你调节，就无法联接网络了，MTU值不懂的，建议不要修改，使用生成配置文件的默认值即可。MTU值的设置可以参考：[wireguard_peer_mtu.csv](https://gist.github.com/nitred/f16850ca48c48c79bf422e90ee5b9d95) 里面的表格的数据尝试修改。
