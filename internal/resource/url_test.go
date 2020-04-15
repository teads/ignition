// Copyright 2015 CoreOS, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package resource

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"net/url"
	"reflect"
	"strings"
	"testing"

	configErrors "github.com/coreos/ignition/v2/config/shared/errors"
	"github.com/coreos/ignition/v2/internal/log"
	"github.com/coreos/ignition/v2/internal/util"
)

func TestAssertValid(t *testing.T) {
	type in struct {
		URL  url.URL
		dest bytes.Buffer
		opts FetchOptions
	}
	type out struct {
		err error
	}

	decodeString := func(s string) []byte {
		byteArray, err := hex.DecodeString(s)
		if err != nil {
			return []byte{}
		}
		return byteArray
	}

	expectedFileContent := `# This file

SELINUX=permissive`

	tests := []struct {
		in  in
		out out
	}{
		{
			in: in{
				URL: url.URL{
					Scheme: "data",
					Opaque: ",%23%20This%20file%0A%0ASELINUX%3Dpermissive",
				},
				dest: bytes.Buffer{},
				opts: FetchOptions{},
			},
			out: out{},
		},
		{
			in: in{
				URL: url.URL{
					Scheme: "data",
					Opaque: ";base64,IyBUaGlzIGZpbGUKClNFTElOVVg9cGVybWlzc2l2ZQo=",
				},
				dest: bytes.Buffer{},
				opts: FetchOptions{},
			},
			out: out{},
		},
		{
			in: in{
				URL: url.URL{
					Scheme: "data",
					Opaque: ";base64,H4sIANFgj14AA1NWCMnILFZIy8xJ5eIKdvXx9AuNsC1ILcrNLC7OLEvlAgDsr0l4IAAAAA==",
				},
				dest: bytes.Buffer{},
				opts: FetchOptions{
					Compression: "gzip",
				},
			},
			out: out{},
		},
		{
			in: in{
				URL: url.URL{
					Scheme: "data",
					Opaque: ",%23%20This%20file%0A%0ASELINUX%3Dpermissive",
				},
				dest: bytes.Buffer{},
				opts: FetchOptions{
					Hash:        sha512.New(),
					ExpectedSum: decodeString("c751b0424f4cee157c83df2e218d91b5d45cfa7c668f72924241b59c81c8f1a752a135d09aa30816f4b4a1570046cc04bcfa26ea9ef70459eedfb01475240838"),
				},
			},
			out: out{},
		},
		{
			in: in{
				URL: url.URL{
					Scheme: "data",
					Opaque: ";base64,IyBUaGlzIGZpbGUKClNFTElOVVg9cGVybWlzc2l2ZQo=",
				},
				dest: bytes.Buffer{},
				opts: FetchOptions{
					Hash:        sha512.New(),
					ExpectedSum: decodeString("58b63cd659fbf2264a4d59e6061bff888c54d0d98dc27a3167a607ce92076e906352f73bce72d563d66dd5322496c7f9542c0d22bb23955d17e4a71784d1155f"),
				},
			},
			out: out{},
		},
		{
			in: in{
				URL: url.URL{
					Scheme: "data",
					Opaque: ";base64,H4sIANFgj14AA1NWCMnILFZIy8xJ5eIKdvXx9AuNsC1ILcrNLC7OLEvlAgDsr0l4IAAAAA==",
				},
				dest: bytes.Buffer{},
				opts: FetchOptions{
					Compression: "gzip",
					Hash:        sha512.New(),
					ExpectedSum: decodeString("58b63cd659fbf2264a4d59e6061bff888c54d0d98dc27a3167a607ce92076e906352f73bce72d563d66dd5322496c7f9542c0d22bb23955d17e4a71784d1155f"),
				},
			},
			out: out{},
		},
		{
			in: in{
				URL: url.URL{
					Scheme: "data",
					Opaque: ",%23%20This%20file%0A%0ASELINUX%3Dpermissive",
				},
				dest: bytes.Buffer{},
				opts: FetchOptions{
					Hash:        sha512.New(),
					ExpectedSum: decodeString("9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043"),
				},
			},
			out: out{err: util.ErrHashMismatch{
				Calculated: "c751b0424f4cee157c83df2e218d91b5d45cfa7c668f72924241b59c81c8f1a752a135d09aa30816f4b4a1570046cc04bcfa26ea9ef70459eedfb01475240838",
				Expected:   "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043",
			}},
		},
		{
			in: in{
				URL: url.URL{
					Scheme: "data",
					Opaque: ";base64,IyBUaGlzIGZpbGUKClNFTElOVVg9cGVybWlzc2l2ZQo=",
				},
				dest: bytes.Buffer{},
				opts: FetchOptions{
					Hash:        sha512.New(),
					ExpectedSum: decodeString("9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043"),
				},
			},
			out: out{err: util.ErrHashMismatch{
				Calculated: "58b63cd659fbf2264a4d59e6061bff888c54d0d98dc27a3167a607ce92076e906352f73bce72d563d66dd5322496c7f9542c0d22bb23955d17e4a71784d1155f",
				Expected:   "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043",
			}},
		},
		{
			in: in{
				URL: url.URL{
					Scheme: "data",
					Opaque: ";base64,H4sIANFgj14AA1NWCMnILFZIy8xJ5eIKdvXx9AuNsC1ILcrNLC7OLEvlAgDsr0l4IAAAAA==",
				},
				dest: bytes.Buffer{},
				opts: FetchOptions{
					Compression: "gzip",
					Hash:        sha512.New(),
					ExpectedSum: decodeString("9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043"),
				},
			},
			out: out{err: util.ErrHashMismatch{
				Calculated: "58b63cd659fbf2264a4d59e6061bff888c54d0d98dc27a3167a607ce92076e906352f73bce72d563d66dd5322496c7f9542c0d22bb23955d17e4a71784d1155f",
				Expected:   "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043",
			}},
		},
		{
			in: in{
				URL: url.URL{
					Scheme: "data",
					Opaque: ";base64,H4sIAATYjl4AA1NWCMnILFZIy8xJ5eJSVgh29fH0C41QSE7MU7DigvJsC1KLcjOLizPLUrkASdQw8zAAAAA=",
				},
				dest: bytes.Buffer{},
				opts: FetchOptions{
					Compression: "unknown",
				},
			},
			out: out{
				err: configErrors.ErrCompressionInvalid,
			},
		},
	}

	logger := log.New(false)
	defer logger.Close()
	f := Fetcher{
		Logger: &logger,
	}

	for i, test := range tests {
		test.in.dest.Reset()
		err := f.fetchFromDataURL(test.in.URL, &test.in.dest, test.in.opts)
		if !reflect.DeepEqual(test.out.err, err) {
			t.Errorf("#%d: bad err: want %+v, got %+v", i, test.out.err, err)
		}
		dest := strings.TrimSuffix(test.in.dest.String(), "\n") //remove trail newline added by base64 decoding (makes test fail)
		if dest != "" && !reflect.DeepEqual(expectedFileContent, dest) {
			t.Errorf("#%d: content not equal: want %+v, got %+v", i, expectedFileContent, test.in.dest.String())
		}
	}
}
