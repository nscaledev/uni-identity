/*
Copyright 2025 the Unikorn Authors.
Copyright 2026 Nscale.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package html

import (
	"bytes"
	_ "embed"
	"text/template"
)

var (
	// errorTemplate defines the HTML used to raise an error to the client.
	//go:embed error.html.tmpl
	errorTemplate string

	// loginTemplate defines the HTML used to acquire an email address from
	// the end user.
	//go:embed login.html.tmpl
	loginTemplate string

	// welcomeEmail defines the HTML used to welcome a user to an organization.
	//go:embed welcome-email.html.tmpl
	welcomeEmailTemplate string
)

// Error renders a default error page.
func Error(errorString, message string) ([]byte, error) {
	tmpl, err := template.New("error").Parse(errorTemplate)
	if err != nil {
		return nil, err
	}

	templateContext := map[string]any{
		"error":   errorString,
		"message": message,
	}

	var buffer bytes.Buffer

	if err := tmpl.Execute(&buffer, templateContext); err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

// Login renders a default login screen.
func Login(state string) ([]byte, error) {
	tmpl, err := template.New("login").Parse(loginTemplate)
	if err != nil {
		return nil, err
	}

	templateContext := map[string]any{
		"state": state,
	}

	var buffer bytes.Buffer

	if err := tmpl.Execute(&buffer, templateContext); err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

// WelcomeEmail returns a default welcome email.
func WelcomeEmail(verifyLink string) ([]byte, error) {
	tmpl, err := template.New("welcome").Parse(welcomeEmailTemplate)
	if err != nil {
		return nil, err
	}

	templateContext := map[string]any{
		"verifyLink": verifyLink,
	}

	var buffer bytes.Buffer

	if err := tmpl.Execute(&buffer, templateContext); err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}
