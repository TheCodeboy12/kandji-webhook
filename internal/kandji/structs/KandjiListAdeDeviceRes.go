package kandji

type KandjiListAdeDeviceRes struct {
	Count    int               `json:"count"`
	Next     string            `json:"next"`
	Previous string            `json:"previous"`
	Results  []kandjiAdeDevice `json:"results"`
}
type depAccount struct {
	Id         string `json:"id"`
	ServerName string `json:"server_name"`
}
type kandjiAdeDevice struct {
	AssetTag     string     `json:"asset_tag"`
	SerialNumber string     `json:"serial_number"`
	Dep_account  depAccount `json:"dep_account"`
	BlueprintId  string     `json:"blueprint_id"`
	Id           string     `json:"id"`
}
