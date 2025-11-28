package tasks

import (
	"fmt"
	"strings"

	"github.com/tdeslauriers/carapace/pkg/validate"
)

// TaskQueryParams is a map of keys that represents the allowed query parameters for a task template.
var TaskQueryParams map[string]struct{} = map[string]struct{}{
	"view":            {},
	"assignee":        {},
	"name":            {},
	"cadence":         {},
	"category":        {},
	"is_complete":     {},
	"is_satisfactory": {},
	"is_proactive":    {},
	"is_archived":     {},
}

// TaskViews is a map of keys that represents the allowed views for a task template.
var TaskViews map[string]struct{} = map[string]struct{}{
	"today": {},
}

// AssigneeCodes is map of keys that represents the allowed assignee shorthand for a task template.
// Note: assignee can also be a username or a user slug (for the allowance table).
var AssigneeCodes map[string]struct{} = map[string]struct{}{
	"me":  {},
	"all": {},
}

// ValidateQueryParams is a function that validates the query parameters for a task template.
// It is used to validate the query parameters passed in the request.
func ValidateQueryParams(params map[string][]string) error {

	// check if params exist
	if len(params) > 0 {

		// check if params are valid
		for k := range params {
			if _, ok := TaskQueryParams[k]; !ok {
				return fmt.Errorf("invalid query parameter: %s", k)
			}
		}

		// check if view exists, and if so, is it valid
		if views, ok := params["view"]; ok {

			// loop the values, and seperate any multiple values into single values
			var viewList []string
			for _, v := range views {

				// split any multiple values into single values, eg, "today,all" => ["today", "all"]
				// because query param functions often make string literals out of arrays/slices.
				// a view name will never have a comma in it, so should be fine.
				// this is a bit of a hack, but it works.
				vs := strings.Split(v, ",")
				for _, v := range vs {
					viewList = append(viewList, strings.TrimSpace(strings.ToLower(v)))
				}
			}

			// check if view is empty
			if len(viewList) <= 0 {
				return fmt.Errorf("view parameter is not allowed to be empty if submitted")
			}

			// check if slice has more than one value
			if len(viewList) > 1 {
				return fmt.Errorf("view parameter must be a single value")
			}

			// dont need to split the values to check for multiple values because
			// no views will ever have commas in them, so it will fail the key check below anyway.

			// check if view is valid
			if _, ok := TaskViews[strings.TrimSpace(strings.ToLower(viewList[0]))]; !ok {
				return fmt.Errorf("invalid view parameter: %s", viewList[0])
			}
		}

		// check if assignees exists, and if so, is it valid
		if assignees, ok := params["assignee"]; ok {

			// loop the values, and seperate any multiple values into single values
			var assigneeList []string
			for _, a := range assignees {

				// split any multiple values into single values, eg, "me,all" => ["me", "all"]
				as := strings.Split(a, ",")
				for _, a := range as {
					assigneeList = append(assigneeList, strings.TrimSpace(strings.ToLower(a)))
				}
			}

			for _, a := range assigneeList {
				// check if assignee is empty
				if len(a) <= 0 {
					return fmt.Errorf("assignee parameter is not allowed to be empty if submitted")
				}

				// check if assignee is valid
				// Note: not allowed to search by email address -> PII + too easy to guess
				// check if valid assignee code
				_, ok := AssigneeCodes[a]
				// check if valid uuid for search as a slug
				if !ok && !validate.IsValidUuid(a) {
					return fmt.Errorf("invalid assignee parameter: %s", a)
				}
			}

			// check that if 'all' is present, it is the only value
			var isAll bool
			if len(assigneeList) > 1 {
				for _, a := range assigneeList {
					if a == "all" {
						isAll = true
						break
					}
				}
			}
			if isAll {
				return fmt.Errorf("assignee parameter(s) cannot be/include 'all' if other user parameter values are present")
			}
		}

		// check if name exists, and if so, is it valid
		if name, ok := params["name"]; ok {
			// check if name is empty
			if len(name) <= 0 {
				return fmt.Errorf("name parameter is not allowed to be empty if submitted")
			}

			if len(name) > 1 {

				// seperate any multiple values into single values
				var nameList []string
				for _, n := range name {

					// split any multiple values into single values, eg, "name1,name2" => ["name1", "name2"]
					ns := strings.Split(n, ",")
					for _, n := range ns {
						nameList = append(nameList, strings.TrimSpace(strings.ToLower(n)))
					}
				}
				// check if name is valid
				for _, n := range nameList {
					if len(n) < 2 || len(n) > 64 {
						return fmt.Errorf("name parameter must be between 2 and 64 characters in length")
					}

					if err := validate.IsValidName(n); err != nil {
						return fmt.Errorf("invalid name parameter: %v", err)
					}
				}
			}
		}

		// check if cadence exists, and if so, is it valid
		if cadence, ok := params["cadence"]; ok {
			// check if cadence is empty
			if len(cadence) <= 0 {
				return fmt.Errorf("cadence parameter is not allowed to be empty if submitted")
			}

			cadenceList := make([]string, 0)
			// loop the values, and seperate any multiple values into single values
			for _, c := range cadence {
				// split any multiple values into single values, eg, "adhoc,daily" => ["adhoc", "daily"]
				cs := strings.Split(c, ",")
				for _, c := range cs {
					cadenceList = append(cadenceList, strings.TrimSpace(strings.ToUpper(c)))
				}
			}

			// artificially declare cadence param(s) a Cadence type to use Cadence.IsValidCadence()
			for _, c := range cadenceList {
				test := Cadence(strings.TrimSpace(strings.ToUpper(c)))
				if (&test).IsValidCadence() != nil {
					return fmt.Errorf("invalid cadence parameter: %s", c)
				}
			}
		}

		// check if category exists, and if so, is it valid
		if category, ok := params["category"]; ok {
			// check if category is empty
			if len(category) <= 0 {
				return fmt.Errorf("category parameter is not allowed to be empty if submitted")
			}

			// loop the values, and seperate any multiple values into single values
			var categoryList []string
			for _, c := range category {
				// split any multiple values into single values, eg, "bills,car" => ["bills", "car"]
				cs := strings.Split(c, ",")
				for _, c := range cs {
					categoryList = append(categoryList, strings.TrimSpace(strings.ToUpper(c)))
				}
			}

			// artificially declare category param(s) a Category type to use Category.IsValidCategory()
			for _, c := range categoryList {
				test := Category(strings.TrimSpace(strings.ToUpper(c)))
				if (&test).IsValidCategory() != nil {
					return fmt.Errorf("invalid category parameter: %s", c)
				}
			}
		}

		// check if is_complete exists, and if so, is it valid
		if isComplete, ok := params["is_complete"]; ok {
			// check if is_complete is empty
			if len(isComplete) <= 0 {
				return fmt.Errorf("is_complete parameter is not allowed to be empty if submitted")
			}

			// loop the values, and seperate any multiple values into single values
			var isCompleteList []string
			for _, ic := range isComplete {
				// split any multiple values into single values, eg, "true,false" => ["true", "false"]
				ics := strings.Split(ic, ",")
				for _, ic := range ics {
					isCompleteList = append(isCompleteList, strings.TrimSpace(strings.ToLower(ic)))
				}
			}

			// cannot be more than one value because that is the same as "all", or "any" ==> unnecessary param
			if len(isCompleteList) > 1 {
				return fmt.Errorf("is_complete parameter must be a single value")
			}

			// check if is_complete is a boolean
			if isCompleteList[0] != "true" && isCompleteList[0] != "false" {
				return fmt.Errorf("invalid is_complete parameter: %s", isCompleteList[0])
			}
		}

		// check if is_satisfactory exists, and if so, is it valid
		if isSatisfactory, ok := params["is_satisfactory"]; ok {
			// check if is_satisfactory is empty
			if len(isSatisfactory) <= 0 {
				return fmt.Errorf("is_satisfactory parameter is not allowed to be empty if submitted")
			}

			// loop the values, and seperate any multiple values into single values
			var isSatisfactoryList []string
			for _, is := range isSatisfactory {
				// split any multiple values into single values, eg, "true,false" => ["true", "false"]
				iss := strings.Split(is, ",")
				for _, is := range iss {
					isSatisfactoryList = append(isSatisfactoryList, strings.TrimSpace(strings.ToLower(is)))
				}
			}

			// cannot be more than one value because that is the same as "all", or "any" ==> unnecessary param
			if len(isSatisfactoryList) > 1 {
				return fmt.Errorf("is_satisfactory parameter must be a single value")
			}

			// check if is_satisfactory is a boolean
			if isSatisfactoryList[0] != "true" && isSatisfactoryList[0] != "false" {
				return fmt.Errorf("invalid is_satisfactory parameter: %s", isSatisfactoryList[0])
			}
		}

		// check if is_proactive exists, and if so, is it valid
		if isProactive, ok := params["is_proactive"]; ok {
			// check if is_proactive is empty
			if len(isProactive) <= 0 {
				return fmt.Errorf("is_proactive parameter is not allowed to be empty if submitted")
			}

			// loop the values, and seperate any multiple values into single values
			var isProactiveList []string
			for _, ip := range isProactive {
				// split any multiple values into single values, eg, "true,false" => ["true", "false"]
				ips := strings.Split(ip, ",")
				for _, ip := range ips {
					isProactiveList = append(isProactiveList, strings.TrimSpace(strings.ToLower(ip)))
				}
			}

			// cannot be more than one value because that is the same as "all", or "any" ==> unnecessary param
			if len(isProactiveList) > 1 {
				return fmt.Errorf("is_proactive parameter must be a single value")
			}

			// check if is_proactive is a boolean
			if isProactiveList[0] != "true" && isProactiveList[0] != "false" {
				return fmt.Errorf("invalid is_proactive parameter: %s", isProactiveList[0])
			}
		}

		// check if is_archived exists, and if so, is it valid
		if isArchived, ok := params["is_archived"]; ok {
			// check if is_archived is empty
			if len(isArchived) <= 0 {
				return fmt.Errorf("is_archived parameter is not allowed to be empty if submitted")
			}

			// loop the values, and seperate any multiple values into single values
			var isArchivedList []string
			for _, ia := range isArchived {
				// split any multiple values into single values, eg, "true,false" => ["true", "false"]
				ias := strings.Split(ia, ",")
				for _, ia := range ias {
					isArchivedList = append(isArchivedList, strings.TrimSpace(strings.ToLower(ia)))
				}
			}

			// cannot be more than one value because that is the same as "all", or "any" ==> unnecessary param
			if len(isArchivedList) > 1 {
				return fmt.Errorf("is_archived parameter must be a single value")
			}

			// check if is_archived is a boolean
			if isArchivedList[0] != "true" && isArchivedList[0] != "false" {
				return fmt.Errorf("invalid is_archived parameter: %s", isArchivedList[0])
			}
		}
	}

	return nil
}
