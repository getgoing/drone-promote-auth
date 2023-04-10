// Copyright 2019 the Drone Authors. All rights reserved.
// Use of this source code is governed by the Blue Oak Model License
// that can be found in the LICENSE file.

package plugin

import (
	"context"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/drone/drone-go/plugin/validator"
)

var (
	restrictedEvents = []string{
		"promote",
		"rollback",
	}
)

func stringInSlice(str string, slice []string) bool {
	for _, item := range slice {
		if str == item {
			return true
		}
	}
	return false
}

// New returns a new validator plugin.
func New(privilegedUsers []string, userPermissionsRaw map[string]string) validator.Plugin {
	userPermissions := make(map[string]map[string][]string)

	// parse list of envs[repos] each user is allowed to promote builds to
	for user, envString := range userPermissionsRaw {
		envMap := make(map[string][]string)
		envs := strings.Split(envString, ";")

		for _, envPerm := range envs {
			envRepo := strings.Split(envPerm, "[")
			env := envRepo[0]

			repoStr := strings.TrimSuffix(strings.TrimPrefix(envRepo[1], "["), "]")

			repos := strings.Split(repoStr, ",")

			envMap[env] = repos

		}
		userPermissions[user] = envMap
	}

	return &plugin{
		privilegedUsers: privilegedUsers,
		userPermissions: userPermissions,
	}
}

type plugin struct {
	privilegedUsers []string
	userPermissions map[string]map[string][]string
}

func (p *plugin) Validate(ctx context.Context, req *validator.Request) error {
	// check if this event requires auth
	if stringInSlice(req.Build.Event, restrictedEvents) {
		// check if user is privilged to promote to any env
		if stringInSlice(req.Build.Trigger, p.privilegedUsers) {
			logrus.Debugf(
				"User %s has been authorized to %s to/on %s env in %s repo as a privileged user",
				req.Build.Trigger, req.Build.Event, req.Build.Deploy, req.Repo.Name,
			)
			return nil
		}

		// check if user has any per-env[repo] permission
		if allowedEnvs, userHasPermissions := p.userPermissions[req.Build.Trigger]; userHasPermissions {
			// check if user is allowed to promote to a requested env

			for env, repos := range allowedEnvs {
				if env == req.Build.Deploy && stringInSlice(req.Repo.Name, repos) {
					logrus.Debugf(
						"User %s has been authorized to %s to/on %s env in %s repo according to user level permissions",
						req.Build.Trigger, req.Build.Event, req.Build.Deploy, req.Repo.Name,
					)
					return nil
				}
			}

		}

		logrus.Debugf("user %s not allowed to %s to/on %s in %s repo", req.Build.Trigger, req.Build.Event, req.Build.Deploy, req.Repo.Name)
		return validator.ErrSkip
	}

	return nil
}
