package tier1

type Profile string

const (
	ProfileProd Profile = "prod"
	ProfileDev  Profile = "dev"
)

func ProfileFromProductionMode(productionMode bool) Profile {
	if productionMode {
		return ProfileProd
	}
	return ProfileDev
}

type Reachability string

const (
	ReachableTrue    Reachability = "true"
	ReachableFalse   Reachability = "false"
	ReachableUnknown Reachability = "unknown"
)

type Result struct {
	Reachable Reachability
	Reason    string
}
