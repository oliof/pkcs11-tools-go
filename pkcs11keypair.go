package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/miekg/pkcs11"
)

type Config struct {
	module    string
	slot_id   uint
	user_pin  string
	key_label string
	key_id    string
	rsa_size  uint
}

func randomKeyID() (string, error) {
	random_key := make([]byte, 2)
	n, err := io.ReadFull(rand.Reader, random_key)
	if n != len(random_key) || err != nil {
		return "", err
	}
	return fmt.Sprintf("%0x%0x", random_key[0], random_key[1]), nil
}

func configure() (config Config) {
	random_id, _ := randomKeyID()
	config = Config{"/usr/lib/softhsm/libsofthsm.so", //module
		0,                     //slot_id
		"0000",                //user_pin
		"pkcs11keypair_label", //key_label
		random_id,             //key_id
		2048,                  //rsa_size
	}

	if len(os.Getenv("HSM_MODULE")) > 0 {
		config.module = os.Getenv("HSM_MODULE")
	}

	if len(os.Getenv("HSM_SLOT_ID")) > 0 {
		env_slot_id, _ := strconv.ParseUint(os.Getenv("HSM_SLOT_ID"), 10, 0)
		config.slot_id = uint(env_slot_id)
	}

	if len(os.Getenv("USER_PIN")) > 0 {
		config.user_pin = os.Getenv("USER_PIN")
	}

	if len(os.Getenv("KEY_LABEL")) > 0 {
		config.key_label = os.Getenv("KEY_LABEL")
	}

	if len(os.Getenv("KEY_ID")) > 0 {
		config.key_id = os.Getenv("KEY_ID")
	}

	if len(os.Getenv("RSA_SIZE")) > 0 {
		env_rsa_size, _ := strconv.ParseUint(os.Getenv("RSA_SIZE"), 10, 0)
		config.rsa_size = uint(env_rsa_size)
	}
	fmt.Printf("Using module %s, ", config.module)
	fmt.Printf("slot ID %v, ", config.slot_id)
	fmt.Printf("user PIN %v, ", config.user_pin)
	fmt.Printf("key id '%v', ", config.key_id)
	fmt.Printf("key label '%s', ", config.key_label)
	fmt.Printf("rsa bit size %v.\n", config.rsa_size)

        if config.rsa_size < 1024 {
            fmt.Printf("RSA size insecure, choose 1024 or more.\n")
            os.Exit(1)
        }
        return config
}

func generate_pkcs11keypair() {
        config :=configure()
	p := pkcs11.New(config.module)
	if p == nil {
		fmt.Printf("Could not initialize pkcs11 with module %s, exiting.\n", config.module)
		os.Exit(1)
	}
	p.Initialize()
	defer p.Destroy()
	defer p.Finalize()

	var used_slot uint = 0
	slots, _ := p.GetSlotList(true)

	for _, slot_id := range slots {
		if slot_id == config.slot_id {
			used_slot = config.slot_id
		}
	}
	fmt.Printf("Wanted slot id %v ", config.slot_id)
	fmt.Printf("and got slot id %v.\n", used_slot)
	session, err := p.OpenSession(used_slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		fmt.Printf("Could not open session. Error: %v\n", err)
		os.Exit(1)
	}
	defer p.CloseSession(session)
	p.Login(session, pkcs11.CKU_USER, config.user_pin)
	defer p.Logout(session)

	info, err := p.GetInfo()
	if err != nil {
		fmt.Printf("GetInfo failed: %v\n", err)
		os.Exit(1)
	} else {
		fmt.Printf("HSM Info:\nManufacturer ID %v\nFlags: %v\nLibrary Description: %v\nLibrary Version: %v.\n",
			info.ManufacturerID, info.Flags, info.LibraryDescription, info.LibraryVersion)
	}
	// var pub_exponent int = 0x010001

	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, config.rsa_size),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{3}),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, config.key_label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, config.key_id),
		pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, "/CN=Harald Wagener"),
	}
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, config.key_label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, config.key_id),
		pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, "/CN=Harald Wagener"),
	}
	pub, priv, err := p.GenerateKeyPair(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
		publicKeyTemplate, privateKeyTemplate)
	if err != nil {
		fmt.Printf("Error generating key pair: %v\n", err)
		os.Exit(1)
	} else {
		fmt.Printf("Key pair generated:\nPublic Key: %v\nPrivate Key: %v\n", pub, priv)
		os.Exit(0)
	}
}

func main() {
	generate_pkcs11keypair()
}
