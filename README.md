【rust语言编写的】wireguard 转换为 nekoray 节点，只需要一个 wg-config.conf 配置文件，再输入一个IP和Port端口，即可生成 nekoray 节点的链接。本程序使用 loop 死循环，可以继续生成nekoray节点的链接，想要退出程序，把黑色窗口关闭即可。

### 1、软件效果截图

- 软件使用简单，直接上图吧。

<img src="images\Snipaste_2023-09-14_17-28-52.png" />

- 下图中，左边为本软件的使用效果截图，右边为导入节点后 NekoBox 软件截图

<img src="images\Snipaste_2023-09-14_17-33-28.png" />



### 2、使用到的工具

在线生成warp的wireguard的配置文件信息：[链接1](https://replit.com/@alialma/WARP-Wireguard-Register)、[链接2](https://replit.com/@kelekekou8/WARPconfig-youtubeBu-Yi-Yang-De-Qiang-Ge)

NekoBox Windows版：https://github.com/MatsuriDayo/nekoray/releases

### 3、温馨提示

WireGuard中的MTU值，修改不同的值，可能有一定几率提升网速，甚至，由原来能正常上网的，后来被你调节，就无法联接网络了，MTU值不懂的，建议不要修改，使用生成配置文件的默认值即可。
