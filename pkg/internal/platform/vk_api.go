package platform

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/theairblow/turnable/pkg/common"
)

// vkCallParticipantsResponse mirrors the VK call participants API response
type vkCallParticipantsResponse struct {
	Response struct {
		Profiles []struct {
			ID         int64  `json:"id"`
			FirstName  string `json:"first_name"`
			LastName   string `json:"last_name"`
			ScreenName string `json:"screen_name"`
		} `json:"profiles"`
		Anonyms []struct {
			ID   int64  `json:"id"`
			Name string `json:"name"`
		} `json:"anonyms"`
	} `json:"response"`
}

// vkFormResponse stores a generic decoded form response from VK endpoints
type vkFormResponse map[string]any

// fetchParticipantNames resolves external participant IDs to display names
func (V *VKHandler) fetchParticipantNames(ctx context.Context, callID, accessToken string, externalIDs map[string]struct{}) (map[string]string, error) {
	ids := make([]string, 0, len(externalIDs))
	for externalID := range externalIDs {
		ids = append(ids, externalID)
	}
	if len(ids) == 0 {
		return map[string]string{}, nil
	}

	form := common.NewValues(
		"call_id", callID,
		"participant_ids", strings.Join(ids, ","),
		"fields", "photo_100,photo_200,sex,screen_name,first_name_gen,is_nft,animated_avatar,custom_names_for_calls",
		"access_token", accessToken,
	)

	body, err := V.postVKFormRaw(ctx, http.MethodPost, vkAPIEndpoint+"/messages.getCallParticipants?v="+vkAPIVersion+"&client_id="+vkClientID, form, nil)
	if err != nil {
		return nil, err
	}

	var decoded vkCallParticipantsResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil, err
	}

	result := make(map[string]string, len(ids))
	for _, profile := range decoded.Response.Profiles {
		name := strings.TrimSpace(profile.FirstName + " " + profile.LastName)
		if name == "" {
			name = profile.ScreenName
		}
		result[strconv.FormatInt(profile.ID, 10)] = name
	}
	for _, anonym := range decoded.Response.Anonyms {
		result[strconv.FormatInt(anonym.ID, 10)] = anonym.Name
	}
	return result, nil
}

// postVKFormRaw performs an HTTP request with all profile headers applied and returns the raw response body.
func (V *VKHandler) postVKFormRaw(ctx context.Context, method, endpoint string, form *common.Values, extraHeaders map[string]string) ([]byte, error) {
	p := V.profile
	httpClient := V.httpClient

	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", p.UserAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Sec-CH-UA", p.SecChUa)
	req.Header.Set("Sec-CH-UA-Mobile", p.SecChUaMobile)
	req.Header.Set("Sec-CH-UA-Platform", p.SecChUaPlatform)
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Origin", "https://vk.com")
	req.Header.Set("Referer", "https://vk.com/")
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

// postVKForm submits a form-encoded POST request and returns a decoded JSON response.
func (V *VKHandler) postVKForm(ctx context.Context, endpoint string, form *common.Values, extraHeaders map[string]string) (vkFormResponse, error) {
	body, err := V.postVKFormRaw(ctx, http.MethodPost, endpoint, form, extraHeaders)
	if err != nil {
		return nil, err
	}

	var out vkFormResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out, nil
}
