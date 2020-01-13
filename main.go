package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/shirou/gopsutil/host"
)

func main() {
	var pass string

	uuid := uuid()
	salt := "dd" + uuid[:8] + uuid[24:] + "dd"
	dir := "C://DenigmaDisk/files"
	d := "e"

	if _, err := os.Stat("C:\\DenigmaDisk\\Settings.dat"); os.IsNotExist(err) {
		os.Mkdir("C://DenigmaDisk", 0644)
		os.Mkdir(dir, 0644)

		var psw string
		var status string
		fmt.Print("Hi! This is the first launch DenigmaDisk. We are very grateful to you. Good Luck!\nEnter Password: ")
		fmt.Fscan(os.Stdin, &psw)

		fmt.Print("\n\nGreat! Do you want to enter your password every time or do we need to remember it?\n1 - remember; 0 - no: ")
		fmt.Fscan(os.Stdin, &status)

		os.Create("C://DenigmaDisk\\Settings.dat")
		file, err := os.OpenFile("C://DenigmaDisk\\Settings.dat", os.O_RDWR, 0644)
		if err != nil {
			panic(err)
		}
		if status == "1" {

			h := sha256.New()
			h.Write([]byte(psw))

			file.WriteString(fmt.Sprintf("%x", h.Sum(nil))[32:])
		} else {
			file.WriteString("FuckYou!DenigmaDiskByZpon")
		}

		file.Sync()

		os.Create("C://DenigmaDisk/Status.log")
		file, err = os.OpenFile("C://DenigmaDisk/Status.log", os.O_RDWR, 0644)
		if err != nil {
			panic(err)
		}
		file.WriteString("Decrypted")
		file.Sync()

	}

	s, _ := os.Open("C://DenigmaDisk/Settings.dat")
	b, _ := ioutil.ReadAll(s)
	s.Close()
	if string(b[:]) == "FuckYou!DenigmaDiskByZpon" {
		fmt.Print("Enter Password: ")
		fmt.Fscan(os.Stdin, &pass)

		h := sha256.New()
		h.Write([]byte(pass))
		pass = fmt.Sprintf("%x", h.Sum(nil))[32:]
	} else {
		pass = string(b[:])
	}

	s, _ = os.Open("C://DenigmaDisk/Status.log")
	b, _ = ioutil.ReadAll(s)
	s.Close()
	if string(b[:]) == "Decrypted" {
		d = "e"
	} else if string(b[:]) == "Encrypted" {
		d = "d"
	} else {
		panic("Error status!")
	}

	fmt.Println("\nStarting...")

	logfile := "C://DenigmaDisk/DenigmaDisk.log"
	os.Create(logfile)
	list := Getfiles(dir, logfile)
	os.Remove(logfile)

	for _, i := range list {
		if i == "" {
			continue
		}

		if isdir(i) {
			//Decrypt dir name
			if d == "d" {
				err := os.Rename(i, filepath.Dir(i)+"/"+string(Decrypter(pass, salt, []byte(filepath.Base(i)))[:]))
				if err != nil {
					panic(err)
				}
				//Encrypt dir name
			} else if d == "e" {
				err := os.Rename(i, filepath.Dir(i)+"/"+string(Encrypter(pass, salt, []byte(filepath.Base(i)))[:]))
				if err != nil {
					panic(err)
				}
			}
		} else {

			openfile, _ := os.Open(i)
			b, _ := ioutil.ReadAll(openfile)
			openfile.Close()

			//Decrypt file and her name
			if d == "d" {
				encoded := Decrypter(pass, salt, b)
				err := ioutil.WriteFile(i, encoded, 0644)
				if err != nil {
					fmt.Println(err)
				}

				if filepath.Ext(i) == ".dgd" {
					err := os.Rename(i, filepath.Dir(i)+"/"+string(Decrypter(pass, salt, []byte(filepath.Base(i[:len(i)-4])))[:]))
					if err != nil {
						panic(err)
					}
				}
				//Encrypt file and her name
			} else if d == "e" {
				encoded := Encrypter(pass, salt, b)
				err := ioutil.WriteFile(i, encoded, 0644)
				if err != nil {
					fmt.Println(err)
				}

				err = os.Rename(i, filepath.Dir(i)+"\\"+string(Encrypter(pass, salt, []byte(filepath.Base(i)))[:])+".dgd")
				if err != nil {
					panic(err)
				}
			}

		}

	}
	file, err := os.OpenFile("C://DenigmaDisk/Status.log", os.O_RDWR, 0644)
	if len(list) == 1 {
		fmt.Println("Not found files!")
		file.WriteString("Decrypted")
		os.Exit(2)
	}
	if err != nil {
		panic(err)
	}
	if d == "d" {

		out, err := exec.Command("subst.exe", "T:", dir).Output()
		if (err != nil) || (len(out) != 0) {
			panic("Ошибка Инициализации диска.")
			os.Exit(2)
		}

		file.WriteString("Decrypted")
		fmt.Println("Decrypted Success!")
	} else if d == "e" {

		out, err := exec.Command("subst.exe", "T:", "/D").Output()
		if (err != nil) || (len(out) != 0) {
			panic("Ошибка Инициализации диска.")
		}

		file.WriteString("Encrypted")
		fmt.Println("Encrypted Success!")
	} else {
		panic("Status ERR")
	}
	file.Sync()

	//Example Encrypt/Decrypt function

	//ab := Encrypter("AES256Key-32Characters1234567890", "dd"+uuid[:8]+uuid[24:]+"dd", []byte("blablabla.exe"))
	//fmt.Println(string(ab[:]))

	//ba := Decrypter("AES256Key-32Characters1234567890", "dd"+uuid[:8]+uuid[24:]+"dd", []byte("2d3804477ccfee591826734d5951c5e7dd7f68"))
	//fmt.Println(string(ba[:]))

}

func uuid() string {

	hostStat, err := host.Info()
	if err != nil {
		panic(err.Error())
	}
	return hostStat.HostID
}

func Encrypter(pass string, uuid string, plaintext []byte) []byte {
	// to select AES-128 or AES-256.
	key := []byte(pass)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	nonce, _ := hex.DecodeString(uuid)
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	return []byte(fmt.Sprintf("%x", ciphertext)[:])
}

func Decrypter(pass string, uuid string, ba []byte) []byte {
	// to select AES-128 or AES-256.
	key := []byte(pass)

	dst := make([]byte, hex.DecodedLen(len(ba)))
	n, _ := hex.Decode(dst, ba)
	ciphertext := dst[:n]
	nonce, _ := hex.DecodeString(uuid)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	return plaintext
}

func Getfiles(dir string, tmp string) []string {

	files, err := ioutil.ReadDir(dir)
	if err != nil {
		panic("Error read dir: " + dir)
		os.Exit(2)
	}

	for _, i := range files {

		if isdir(dir + "\\" + i.Name()) {
			file, _ := os.OpenFile(tmp, os.O_RDWR|os.O_APPEND, 0644)
			file.WriteString(dir + "\\" + i.Name() + "\n")
			file.Sync()

			Getfiles(dir+"\\"+i.Name(), tmp)

		} else {

			file, _ := os.OpenFile(tmp, os.O_RDWR|os.O_APPEND, 0644)
			file.WriteString(dir + "\\" + i.Name() + "\n")
			file.Sync()
		}
	}
	reversed := []string{}
	file, _ := os.Open(tmp)
	b, _ := ioutil.ReadAll(file)
	arr := strings.Split(string(b), "\n")

	for i := range arr {
		n := arr[len(arr)-1-i]
		reversed = append(reversed, n)
	}
	return reversed
}

func isdir(path string) bool {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false
	}
	return fileInfo.IsDir()
}
