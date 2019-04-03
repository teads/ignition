// Copyright 2019 Red Hat, Inc.
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

package v3_1

import (
	"github.com/coreos/ignition/config/translate"
	old_types "github.com/coreos/ignition/config/v3_0/types"
	"github.com/coreos/ignition/config/v3_1_experimental/types"
)

func translateIgnition(old old_types.Ignition) (ret types.Ignition) {
	// use a new translator so we don't recurse infintitely
	translate.NewTranslator().Translate(&old, &ret)
	ret.Version = types.MaxVersion.String()
	return
}


func Translate(old old_types.Config) (ret types.Config) {
	tr := translate.NewTranslator()
	tr.AddCustomTranslator(translateIgnition)
	tr.Translate(&old, &ret)
	return
}
