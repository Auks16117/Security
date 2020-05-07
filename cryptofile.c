/*
	ver. Shift JIS
	使い方：
  1.平文を作る(8bit, 2進数)
	　　ex: 10001011
	2.パスワードを設定する
	　　ex: 235
	3.実行する
	暗号化: cryptofile enc password plain.txt enc1.txt
	復号: cryptofile dec password enc2.txt dec.txt
	*注意*
	password:パスワード(10bit, 10進数表記, 0