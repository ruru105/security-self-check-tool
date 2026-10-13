# -*- coding: utf-8 -*-
"""
セキュリティ公開前チェックツール 用 100項目チェックリスト定義

各項目:
  id       : 通し番号 (1-100)
  category : カテゴリID (CATEGORIES を参照)
  item     : チェック項目(日本語)
  hint     : 対応のヒント
  auto     : True の場合、自動チェック(bandit / pip-audit / detect-secrets)が
             部分的にでもカバーしている可能性がある項目であることを示す目安。
             あくまで目安であり、自動チェックに通っても手動確認は推奨。
"""

CATEGORIES = {
    "secrets": "1. 秘密情報・認証情報の管理",
    "injection": "2. 入力値検証・インジェクション対策",
    "auth": "3. 認証・認可",
    "deps": "4. 依存ライブラリ・サプライチェーン",
    "config": "5. 設定・環境",
    "logging": "6. ログ・エラー処理",
    "network": "7. 通信・暗号化",
    "privacy": "8. データ保護・プライバシー",
}

CHECKLIST = [
    # 1. 秘密情報・認証情報の管理 (15)
    {"id": 1, "category": "secrets", "item": "APIキー・トークンがコードに直接書かれていないか", "hint": "環境変数や秘密情報管理サービスから読み込む", "auto": True},
    {"id": 2, "category": "secrets", "item": "パスワードがコードに直接書かれていないか", "hint": "環境変数や秘密情報管理サービスから読み込む", "auto": True},
    {"id": 3, "category": "secrets", "item": ".envファイルが.gitignoreに含まれているか", "hint": ".gitignoreに.envを追加する", "auto": False},
    {"id": 4, "category": "secrets", "item": ".envファイルが誤ってGitHubに公開されていないか", "hint": "公開済みなら鍵を失効・再発行し、履歴からも削除する", "auto": True},
    {"id": 5, "category": "secrets", "item": "設定ファイル(config.json等)に秘密情報が含まれていないか", "hint": "秘密情報だけ別ファイル・環境変数に分離する", "auto": True},
    {"id": 6, "category": "secrets", "item": "サンプルコード・README内に実際のキーが載っていないか", "hint": "ダミー値(例: YOUR_API_KEY)に置き換える", "auto": False},
    {"id": 7, "category": "secrets", "item": "データベース接続文字列に認証情報が直書きされていないか", "hint": "接続文字列も環境変数から組み立てる", "auto": True},
    {"id": 8, "category": "secrets", "item": "クラウドサービスのアクセスキーがハードコードされていないか", "hint": "IAMロールや環境変数を利用する", "auto": True},
    {"id": 9, "category": "secrets", "item": "秘密情報は環境変数・秘密情報管理サービスから読み込んでいるか", "hint": "os.environ等で読み込む設計にする", "auto": False},
    {"id": 10, "category": "secrets", "item": "Gitの履歴(過去のコミット)に秘密情報が残っていないか", "hint": "見つかった場合は鍵を失効し、履歴を書き換える", "auto": False},
    {"id": 11, "category": "secrets", "item": "秘密情報を含むログが出力されていないか", "hint": "ログ出力前にマスキングする", "auto": False},
    {"id": 12, "category": "secrets", "item": "テストコードに実際の認証情報が使われていないか", "hint": "テスト用のダミー値を使う", "auto": True},
    {"id": 13, "category": "secrets", "item": "暗号化キー・署名キーがソースコードに含まれていないか", "hint": "鍵管理サービスや環境変数で管理する", "auto": True},
    {"id": 14, "category": "secrets", "item": "秘密情報のローテーション(定期的な更新)手順があるか", "hint": "更新手順をドキュメント化する", "auto": False},
    {"id": 15, "category": "secrets", "item": "公開リポジトリと秘密情報を含む設定が明確に分離されているか", "hint": "公開用と秘密情報用でリポジトリ・ファイルを分ける", "auto": False},

    # 2. 入力値検証・インジェクション対策 (15)
    {"id": 16, "category": "injection", "item": "SQL文を文字列結合で組み立てていないか(SQLインジェクション対策)", "hint": "プレースホルダ(パラメータ化クエリ)を使う", "auto": True},
    {"id": 17, "category": "injection", "item": "ユーザー入力をそのままシェルコマンドに渡していないか", "hint": "shell=Trueを避け、引数をリストで渡す", "auto": True},
    {"id": 18, "category": "injection", "item": "eval()やexec()にユーザー入力を渡していないか", "hint": "ast.literal_evalなど安全な代替手段を使う", "auto": True},
    {"id": 19, "category": "injection", "item": "ファイルパスの組み立てでディレクトリトラバーサル対策をしているか", "hint": "パスを正規化し、許可ディレクトリ内かを検証する", "auto": False},
    {"id": 20, "category": "injection", "item": "アップロードされたファイルの種類・サイズを検証しているか", "hint": "拡張子・MIMEタイプ・サイズ上限をチェックする", "auto": False},
    {"id": 21, "category": "injection", "item": "フォーム入力の文字数・形式を検証しているか", "hint": "サーバー側でバリデーションを行う", "auto": False},
    {"id": 22, "category": "injection", "item": "HTMLに出力する文字列をエスケープしているか(XSS対策)", "hint": "テンプレートエンジンの自動エスケープを有効にする", "auto": False},
    {"id": 23, "category": "injection", "item": "XMLパーサーが外部実体参照(XXE)を無効化しているか", "hint": "defusedxml等の安全なライブラリを使う", "auto": True},
    {"id": 24, "category": "injection", "item": "pickleなど、信頼できないデータの直列化・復元を避けているか", "hint": "JSON等、安全な形式に置き換える", "auto": True},
    {"id": 25, "category": "injection", "item": "正規表現が複雑すぎてDoSを招かないか(ReDoS対策)", "hint": "バックトラックが爆発しないパターンに見直す", "auto": False},
    {"id": 26, "category": "injection", "item": "APIのリクエストパラメータを型・範囲でチェックしているか", "hint": "スキーマ検証ライブラリを使う", "auto": False},
    {"id": 27, "category": "injection", "item": "ファイルアップロード先がシステムの重要な場所でないか", "hint": "専用のアップロード用ディレクトリに限定する", "auto": False},
    {"id": 28, "category": "injection", "item": "CSVインジェクション対策があるか(Excelで数式実行される問題)", "hint": "先頭が=等の値は無害化してから出力する", "auto": False},
    {"id": 29, "category": "injection", "item": "テンプレートエンジンにユーザー入力をそのまま渡していないか", "hint": "テンプレート文字列自体をユーザー入力にしない", "auto": False},
    {"id": 30, "category": "injection", "item": "入力値検証をクライアント側だけでなくサーバー側でも行っているか", "hint": "クライアント側は利便性、サーバー側を正とする", "auto": False},

    # 3. 認証・認可 (15)
    {"id": 31, "category": "auth", "item": "パスワードは平文でなくハッシュ化して保存しているか", "hint": "bcrypt等の専用ハッシュ関数を使う", "auto": False},
    {"id": 32, "category": "auth", "item": "パスワードのハッシュ化にMD5やSHA1を使っていないか", "hint": "bcrypt / argon2等に置き換える", "auto": True},
    {"id": 33, "category": "auth", "item": "ログイン試行回数に制限があるか(ブルートフォース対策)", "hint": "一定回数失敗したら一時ロックする", "auto": False},
    {"id": 34, "category": "auth", "item": "セッションIDが推測されにくい十分な長さ・ランダム性を持っているか", "hint": "暗号論的に安全な乱数生成を使う", "auto": False},
    {"id": 35, "category": "auth", "item": "ログアウト時にセッションが確実に無効化されているか", "hint": "サーバー側でもセッションを破棄する", "auto": False},
    {"id": 36, "category": "auth", "item": "パスワードの最低強度(文字数・複雑さ)を求めているか", "hint": "最低文字数・文字種のルールを設ける", "auto": False},
    {"id": 37, "category": "auth", "item": "多要素認証(MFA)の導入を検討しているか", "hint": "重要な操作にはMFAを検討する", "auto": False},
    {"id": 38, "category": "auth", "item": "権限のないユーザーが他人のデータにアクセスできないか", "hint": "リクエストごとに所有者チェックを行う", "auto": False},
    {"id": 39, "category": "auth", "item": "管理者権限とユーザー権限が適切に分離されているか", "hint": "ロールベースのアクセス制御を導入する", "auto": False},
    {"id": 40, "category": "auth", "item": "APIエンドポイントごとに必要な権限チェックが行われているか", "hint": "認可処理を共通化し、漏れを防ぐ", "auto": False},
    {"id": 41, "category": "auth", "item": "パスワードリセットのトークンが推測されにくく有効期限があるか", "hint": "ランダムトークン+短い有効期限を設定する", "auto": False},
    {"id": 42, "category": "auth", "item": "アカウントロック・凍結の仕組みがあるか", "hint": "不審なアクセスを検知したらロックする", "auto": False},
    {"id": 43, "category": "auth", "item": "デフォルトパスワード(初期パスワード)が残っていないか", "hint": "初回ログイン時に変更を必須にする", "auto": False},
    {"id": 44, "category": "auth", "item": "Cookieにsecure属性・httpOnly属性が設定されているか", "hint": "Cookie発行時に両属性を付与する", "auto": False},
    {"id": 45, "category": "auth", "item": "CSRF対策(トークン等)があるか", "hint": "CSRFトークンの検証を実装する", "auto": False},

    # 4. 依存ライブラリ・サプライチェーン (10)
    {"id": 46, "category": "deps", "item": "使用しているライブラリに既知の脆弱性(CVE)がないか", "hint": "pip-audit等で定期的にスキャンする", "auto": True},
    {"id": 47, "category": "deps", "item": "ライブラリのバージョンが古すぎないか", "hint": "定期的にアップデートする", "auto": True},
    {"id": 48, "category": "deps", "item": "requirements.txt等でバージョンを固定しているか", "hint": "==でバージョンを明記する", "auto": False},
    {"id": 49, "category": "deps", "item": "使われていない(不要な)ライブラリが残っていないか", "hint": "未使用の依存を定期的に棚卸しする", "auto": False},
    {"id": 50, "category": "deps", "item": "ライブラリのライセンスが利用目的と合っているか", "hint": "商用利用の可否をライセンスで確認する", "auto": False},
    {"id": 51, "category": "deps", "item": "インストール元が公式のパッケージレジストリか", "hint": "PyPI公式等、信頼できる配布元のみ使う", "auto": False},
    {"id": 52, "category": "deps", "item": "タイポスクワッティング(似た名前の偽パッケージ)に注意しているか", "hint": "パッケージ名のスペルを確認してからインストールする", "auto": False},
    {"id": 53, "category": "deps", "item": "依存関係の脆弱性チェックを定期的に(自動で)実行しているか", "hint": "CIにpip-audit等を組み込む", "auto": False},
    {"id": 54, "category": "deps", "item": "サードパーティのコード(コピペ含む)の出どころを把握しているか", "hint": "出典とライセンスを記録しておく", "auto": False},
    {"id": 55, "category": "deps", "item": "ビルド・CI環境のツールやアクションも最新か", "hint": "GitHub Actions等のバージョンも更新する", "auto": False},

    # 5. 設定・環境 (15)
    {"id": 56, "category": "config", "item": "本番環境でデバッグモードが有効になっていないか", "hint": "本番ではDEBUG=False等に設定する", "auto": True},
    {"id": 57, "category": "config", "item": "本番環境で詳細なエラーメッセージがそのまま表示されていないか", "hint": "利用者向けには簡潔なメッセージのみ表示する", "auto": False},
    {"id": 58, "category": "config", "item": "サーバーが0.0.0.0など全アドレスで不必要に待ち受けていないか", "hint": "必要な範囲のアドレスに限定する", "auto": True},
    {"id": 59, "category": "config", "item": "不要なポート・サービスが開いていないか", "hint": "使っていないポートは閉じる", "auto": False},
    {"id": 60, "category": "config", "item": "管理画面に外部から誰でもアクセスできてしまわないか", "hint": "IP制限や認証を管理画面にかける", "auto": False},
    {"id": 61, "category": "config", "item": "ファイル・ディレクトリの権限が必要以上に緩くなっていないか", "hint": "必要最小限の権限に絞る", "auto": False},
    {"id": 62, "category": "config", "item": "一時ファイルの作成場所・権限が適切か", "hint": "安全な一時ディレクトリ・関数を使う", "auto": True},
    {"id": 63, "category": "config", "item": "本番・開発・テストで設定ファイルが明確に分かれているか", "hint": "環境ごとに設定ファイルを分離する", "auto": False},
    {"id": 64, "category": "config", "item": "デフォルト設定のまま使われている危険な項目がないか", "hint": "初期設定を見直し、必要に応じて変更する", "auto": False},
    {"id": 65, "category": "config", "item": "サーバーのソフトウェアバージョン情報が外部に漏れていないか", "hint": "レスポンスヘッダー等からバージョン情報を消す", "auto": False},
    {"id": 66, "category": "config", "item": "不要なHTTPメソッド(TRACE等)が有効になっていないか", "hint": "使わないメソッドを無効化する", "auto": False},
    {"id": 67, "category": "config", "item": "CORSの設定が必要以上に緩くなっていないか(全オリジン許可等)", "hint": "許可するオリジンを必要な範囲に限定する", "auto": False},
    {"id": 68, "category": "config", "item": "バックアップファイルが公開ディレクトリに残っていないか", "hint": "バックアップは非公開の場所に保管する", "auto": False},
    {"id": 69, "category": "config", "item": ".gitや.envなど隠しファイルが公開サーバーから閲覧できないか", "hint": "Webサーバー設定でアクセスを拒否する", "auto": False},
    {"id": 70, "category": "config", "item": "コンテナ・サーバーがroot権限で不必要に実行されていないか", "hint": "一般権限のユーザーで実行する", "auto": False},

    # 6. ログ・エラー処理 (10)
    {"id": 71, "category": "logging", "item": "ログにパスワードやカード番号などの秘密情報が出ていないか", "hint": "ログ出力前にマスキングする", "auto": False},
    {"id": 72, "category": "logging", "item": "例外がすべて握りつぶされず、適切に処理・記録されているか", "hint": "空のexceptを避け、ログに残す", "auto": True},
    {"id": 73, "category": "logging", "item": "利用者向けエラーメッセージに内部の仕組みの詳細が出ていないか", "hint": "利用者向けと開発者向けのログを分ける", "auto": False},
    {"id": 74, "category": "logging", "item": "重要な操作(ログイン・削除等)の履歴が記録されているか", "hint": "監査ログとして別途記録する", "auto": False},
    {"id": 75, "category": "logging", "item": "ログが改ざんされにくい形で保存・管理されているか", "hint": "ログの書き込み専用権限などを検討する", "auto": False},
    {"id": 76, "category": "logging", "item": "ログのサイズ・保存期間が管理されているか", "hint": "ログローテーションを設定する", "auto": False},
    {"id": 77, "category": "logging", "item": "異常なアクセス・エラーが多発した際に気づける仕組みがあるか", "hint": "アラート通知の仕組みを検討する", "auto": False},
    {"id": 78, "category": "logging", "item": "ログレベル(info/warning/error)が適切に使い分けられているか", "hint": "重要度に応じたレベルで出力する", "auto": False},
    {"id": 79, "category": "logging", "item": "本番環境で開発用のデバッグ出力が残っていないか", "hint": "print文等のデバッグ出力を削除・無効化する", "auto": False},
    {"id": 80, "category": "logging", "item": "個人情報を含むログへのアクセスが制限されているか", "hint": "ログ閲覧権限を必要な人だけに絞る", "auto": False},

    # 7. 通信・暗号化 (10)
    {"id": 81, "category": "network", "item": "通信がHTTPSで暗号化されているか(HTTP平文通信が残っていないか)", "hint": "全ページをHTTPSに統一する", "auto": False},
    {"id": 82, "category": "network", "item": "SSL/TLS証明書の検証を無効化していないか", "hint": "verify=False等の無効化を外す", "auto": True},
    {"id": 83, "category": "network", "item": "古い・脆弱な暗号化方式(DES、RC4等)を使っていないか", "hint": "AES等、現在推奨される方式を使う", "auto": True},
    {"id": 84, "category": "network", "item": "弱いハッシュ関数(MD5、SHA1)を暗号用途に使っていないか", "hint": "SHA-256以上を使う", "auto": True},
    {"id": 85, "category": "network", "item": "乱数生成に暗号用途として不適切な関数(random等)を使っていないか", "hint": "secretsモジュール等を使う", "auto": True},
    {"id": 86, "category": "network", "item": "APIキーやトークンがURLパラメータに平文で含まれていないか", "hint": "ヘッダーやボディで送る", "auto": False},
    {"id": 87, "category": "network", "item": "証明書の有効期限が切れていないか、更新の仕組みがあるか", "hint": "自動更新や期限監視を設定する", "auto": False},
    {"id": 88, "category": "network", "item": "内部通信(サーバー間等)も暗号化されているか", "hint": "内部通信もTLS化を検討する", "auto": False},
    {"id": 89, "category": "network", "item": "古いバージョンのTLS(TLS1.0/1.1等)を許可していないか", "hint": "TLS1.2以上のみ許可する", "auto": False},
    {"id": 90, "category": "network", "item": "メール送信時の内容が暗号化・保護されているか", "hint": "必要に応じて送信内容を暗号化する", "auto": False},

    # 8. データ保護・プライバシー (10)
    {"id": 91, "category": "privacy", "item": "個人情報を必要以上に収集・保存していないか", "hint": "必要最小限の項目に絞る", "auto": False},
    {"id": 92, "category": "privacy", "item": "不要になった個人情報を削除する仕組みがあるか", "hint": "保存期間を決め、期限後に削除する", "auto": False},
    {"id": 93, "category": "privacy", "item": "データベースのバックアップにも適切なアクセス制限がかかっているか", "hint": "バックアップも本体同様に保護する", "auto": False},
    {"id": 94, "category": "privacy", "item": "テスト・開発環境で実在の個人情報をそのまま使っていないか", "hint": "架空データ・匿名化データに置き換える", "auto": False},
    {"id": 95, "category": "privacy", "item": "データのエクスポート機能に意図しない情報が含まれていないか", "hint": "出力項目を必要な範囲に絞る", "auto": False},
    {"id": 96, "category": "privacy", "item": "第三者にデータを渡す場合、匿名化・仮名化を検討しているか", "hint": "個人を特定できない形に加工する", "auto": False},
    {"id": 97, "category": "privacy", "item": "利用者がデータを確認・削除できる窓口があるか", "hint": "問い合わせ・削除依頼の窓口を用意する", "auto": False},
    {"id": 98, "category": "privacy", "item": "データの保存場所(国・地域)がプライバシー規制と合っているか", "hint": "保存先リージョンを確認する", "auto": False},
    {"id": 99, "category": "privacy", "item": "画面共有・スクリーンショットに個人情報が映り込まないよう配慮しているか", "hint": "デモ用のダミーデータを用意する", "auto": False},
    {"id": 100, "category": "privacy", "item": "退職・契約終了時にアクセス権限やデータが適切に処理されるか", "hint": "権限剥奪・データ返却の手順を決めておく", "auto": False},
]

assert len(CHECKLIST) == 100
