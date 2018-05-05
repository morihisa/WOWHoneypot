# WOWHoneypot: 初心者向け! 攻撃者をおもてなしする Web ハニーポット

Welcome to Omotenashi Web Honeypot(WOWHoneypot)は、簡単に構築可能で、シンプルな機能で動作を把握しやすくした、サーバ側低対話型の入門用 Web ハニーポットです。
ルールベースのマッチ&レスポンス機能により、攻撃者に気持ちよく攻撃してもらい、得られるログの幅を広げることができます。

送信元からの HTTP リクエストをそのまま保存するので、後からじっくりゆっくりログ分析をすることが可能です。

ハニーポッター技術交流会で発表したときの資料はこちらで公開しています。  
[初心者向けハニーポット WOWHoneypot の紹介](https://speakerdeck.com/morihi_soc/chu-xin-zhe-xiang-kehanihotuto-wowhoneypot-falseshao-jie)

## 特徴
- 構築が簡単
- HTTP リクエストをまるっと保存
- デフォルト200 OK
- マッチ&レスポンス

## 必要なもの
- Python3

## 構築方法(Ubuntu 16.04 Server 64bit)
```
$ sudo ufw default DENY
$ sudo ufw allow 80/tcp
$ sudo ufw allow 8080/tcp
※ SSH のアクセスポートも環境に合わせて追加してください。
$ sudo ufw enable
$ sudo vi /etc/ufw/before.rules
※ 「*filter」より前に下記の4行を追記する。
———————————————————————————
*nat
:PREROUTING ACCEPT [0:0]
-A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
COMMIT
———————————————————————————
$ sudo ufw reload
$ cd ~/
$ git clone https://github.com/morihisa/WOWHoneypot.git wowhoneypot
$ cd wowhoneypot
$ python3 ./wowhoneypot.py
```

## 動作確認
- ブラウザでハニーポットの IP アドレスにアクセスして、何かしらの HTML ファイルが返ってきたら OK です。

## ログファイル
- log/wowhoneypot.log
- WOWHoneypot の動作ログが記録されます。
- log/access_log
- アクセスログが記録されます。

## ハンティング機能(WOWHoneypot 1.1 で追加)
- ハンティング機能は、あらかじめ指定しておいた文字列が、要求内容に含まれていた場合に、その文字列をログとして保存します。
- 使い方の例として、wget のようなファイルをダウンロードするコマンドに続いて URL が指定されている文字列を抽出することができます。
- デフォルト設定では無効化されています。利用する場合は、config.txt の「hunt_enable」をTrueに変更してください。
- 抽出する文字列は、art ディレクトリの huntrules.txt ファイルに1行につき1つ指定してください(正規表現で指定可能)。
- 抽出したログは、log ディレクトリの hunting.log に保存されます(\[日時\] 送信元IP 一致した文字列)。  
---
- hunting.log ファイルから、URL を抽出して VirusTotal へサブミットするサンプルスクリプト(chase-url.py)を公開しました。
- chase-url.py を利用する場合、requests ライブラリが必要です($ pip install requests)。
- 実行前に、VirusTotal API Key を取得して、chase-url.py に記載してください。
- サブミットするファイルは、メモリへキャッシュとして保存しますが、ディスクには保存しません。

## 動作テスト済み環境
- macOS High Sierra & Python 3.6.3
- Ubuntu 16.04.3 Server 64bit & Python 3.5.2
- Windows 7 SP1 & Python 3.6.3

## リリースノート
- 2018年5月5日 WOWHoneypot Version 1.1 公開
  - 新機能：ハンティング機能を追加しました。
  - 改善：セッションタイムアウトの処理を見直しました。
  - 改善：URL にスペースが入っている場合、エラーとなっていたため、mrr 処理前に%20に変換するようにしました。
- 2017年11月25日 WOWHoneypot Version 1.0 公開

## Licence

[BSD License](https://github.com/morihisa/WOWHoneypot/blob/master/LICENSE)

## Author

- [morihi-soc.net](http://www.morihi-soc.net/)
- [@morihi_soc](https://twitter.com/morihi_soc)
