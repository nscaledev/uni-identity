/*
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

package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	coreclient "github.com/unikorn-cloud/core/pkg/testing/client"
)

// testObjectName matches uniqueName output with no end anchor, so a name an update spec
// extended with "-updated" still matches.
var testObjectName = regexp.MustCompile(`^test-(project|provider|sa|group)-[0-9]{8}-[0-9]{6}-[0-9a-f]{8}`)

func isTestObjectName(name string) bool {
	return testObjectName.MatchString(name)
}

func isTestUserSubject(config *TestConfig, subject string) bool {
	return strings.HasSuffix(subject, UserSubject(config, ""))
}

// OrganizationRenameSuffix is what the organization update spec appends to the name.
const OrganizationRenameSuffix = "-updated"

func originalOrganizationName(name string) string {
	for strings.HasSuffix(name, OrganizationRenameSuffix) {
		name = strings.TrimSuffix(name, OrganizationRenameSuffix)
	}

	return name
}

// Sweep deletes the test objects a run left in the test organization, and undoes a rename the
// organization update spec did not get to restore. Standing fixtures do not match and stay.
// Projects and service accounts go before groups, because both reference groups.
//
//nolint:cyclop // One flat pass per kind; splitting it would hide the delete order.
func Sweep(ctx context.Context, client *APIClient, config *TestConfig, log io.Writer) error {
	var errs []error

	remove := func(kind, name string, del func() error) {
		err := del()
		if errors.Is(err, coreclient.ErrResourceNotFound) {
			err = nil
		}

		if err != nil {
			errs = append(errs, fmt.Errorf("delete %s %s: %w", kind, name, err))
			return
		}

		fmt.Fprintf(log, "deleted %s %s\n", kind, name)
	}

	projects, err := client.ListProjects(ctx, config.OrgID)
	errs = append(errs, err)

	for _, p := range projects {
		if isTestObjectName(p.Metadata.Name) && p.Metadata.ProvisioningStatus != coreapi.ResourceProvisioningStatusDeprovisioning {
			remove("project", p.Metadata.Name, func() error { return client.DeleteProject(ctx, config.OrgID, p.Metadata.Id) })
		}
	}

	providers, err := client.ListOauth2Providers(ctx, config.OrgID)
	errs = append(errs, err)

	for _, p := range providers {
		if isTestObjectName(p.Metadata.Name) {
			remove("oauth2 provider", p.Metadata.Name, func() error { return client.DeleteOauth2Provider(ctx, config.OrgID, p.Metadata.Id) })
		}
	}

	serviceAccounts, err := client.ListServiceAccounts(ctx, config.OrgID)
	errs = append(errs, err)

	for _, sa := range serviceAccounts {
		if isTestObjectName(sa.Metadata.Name) {
			remove("service account", sa.Metadata.Name, func() error { return client.DeleteServiceAccount(ctx, config.OrgID, sa.Metadata.Id) })
		}
	}

	groups, err := client.ListGroups(ctx, config.OrgID)
	errs = append(errs, err)

	for _, g := range groups {
		if isTestObjectName(g.Metadata.Name) {
			remove("group", g.Metadata.Name, func() error { return client.DeleteGroup(ctx, config.OrgID, g.Metadata.Id) })
		}
	}

	users, err := client.ListUsers(ctx, config.OrgID)
	errs = append(errs, err)

	for _, u := range users {
		if isTestUserSubject(config, u.Spec.Subject) {
			remove("user", u.Spec.Subject, func() error { return client.DeleteUser(ctx, config.OrgID, u.Metadata.Id) })
		}
	}

	org, err := client.GetOrganization(ctx, config.OrgID)
	if err != nil {
		return errors.Join(append(errs, err)...)
	}

	if name := originalOrganizationName(org.Metadata.Name); name != org.Metadata.Name {
		if err := client.UpdateOrganization(ctx, config.OrgID, NewOrganizationPayload().FromRead(*org).WithName(name).Build()); err != nil {
			errs = append(errs, fmt.Errorf("restore organization name %s: %w", name, err))
		} else {
			fmt.Fprintf(log, "renamed organization %s to %s\n", org.Metadata.Name, name)
		}
	}

	return errors.Join(errs...)
}
