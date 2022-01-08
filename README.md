## 0x01安装
```bash
git clone https://github.com/wjlin0/Discuz_Ml_Getshell.git
cd Discuz_Ml_Getshell
python -m venv .venv
# linux
source .venv/bin/activate 
# windows 
# ./venv/Scripts/activate

pip3 install -r requirements.rxt
```
## 0x02 使用
```bash
# 脚本当前目录下
#linux
source .venv/bin/activate
# windows
# ./venv/Scripts/activate

# 指定url
python Getshell.py --url www.example.com

# 指定文件
python Getshell.py --file example.txt
# 添加代理
python Getshell.py --proxy socks5://127.0.0.1:53201 --proxy_cred=admin:admin --url www.example.com

# 指定输出文件位置
python Getshell.py --url www.example.com --outfile /tmp/outfile.txt

```