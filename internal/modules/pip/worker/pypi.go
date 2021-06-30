// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"
	"spdx-sbom-generator/internal/models"
	"strings"
)

var errorPackageDigestNotFound = fmt.Errorf("Digest not found")
var errorPypiCouldNotFetchPkgData = fmt.Errorf("Could not fetch package data from PyPI")

type PypiPackageData struct {
	Info PypiPackageInfo       `json:"info"`
	Urls []PypiPackageDistInfo `json:"urls"`
}

type PypiPackageInfo struct {
	Author                 string   `json:"author"`
	AuthorEmail            string   `json:"author_email"`
	BugTrackURL            string   `json:"bugtrack_url"`
	Classifiers            []string `json:"classifiers"`
	Description            string   `json:"description"`
	DescriptionContentType string   `json:"description_content_type"`
	DocsURL                string   `json:"docs_url"`
	DownloadURL            string   `json:"download_url"`
	HomePageURL            string   `json:"home_page"`
	Keywords               string   `json:"keywords"`
	License                string   `json:"license"`
	Maintainer             string   `json:"maintainer"`
	MaintainerEmail        string   `json:"maintainer_email"`
	Name                   string   `json:"name"`
	PackageURL             string   `json:"package_url"`
	Platform               string   `json:"platform"`
	ProjectURL             string   `json:"project_url"`
	ReleaseURL             string   `json:"release_url"`
	RequiresDist           []string `json:"requires_dist"`
	RequiresPython         string   `json:"requires_python"`
	Summary                string   `json:"summary"`
	Version                string   `json:"version"`
	Yanked                 bool     `json:"yanked"`
	YankedReason           string   `json:"yanked_reason"`
}

type PypiPackageDistInfo struct {
	CommentText    string      `json:"comment_text"`
	Digests        DigestTypes `json:"digests"`
	Downloads      int         `json:"downloads"`
	Filename       string      `json:"filename"`
	HasSig         bool        `json:"has_sig"`
	MD5Digest      string      `json:"md5_digest"`
	PackageType    string      `json:"packagetype"`
	PythonVersion  string      `json:"python_version"`
	RequiresPython string      `json:"requires_python"`
	URL            string      `json:"url"`
	Yanked         bool        `json:"yanked"`
	YankedReason   string      `json:"yanked_reason"`
}

type DigestTypes struct {
	MD5    string `json:"md5"`
	SHA256 string `json:"sha256"`
}

type PackageDigest struct {
	Filename    string
	PackageType string
	Digests     DigestTypes
	DownloadURL string
}

// Order in which we want to pick the package digest
var HashAlgoPickOrder []models.HashAlgorithm = []models.HashAlgorithm{
	models.HashAlgoSHA512,
	models.HashAlgoSHA384,
	models.HashAlgoSHA256,
	models.HashAlgoSHA224,
	models.HashAlgoSHA1,
	models.HashAlgoMD6,
	models.HashAlgoMD5,
	models.HashAlgoMD4,
	models.HashAlgoMD2}

func getPypiPackageChecksumAndDownloadURL(packagename string, packageJsonURL string, checkfortag bool, wheeltag string) (models.CheckSum, string) {
	checksum := models.CheckSum{
		Algorithm: models.HashAlgoSHA1,
	}

	packagedigests, err := fetchAndDecodePypiPackageDataJSON(packagename, packageJsonURL)
	if err != nil {
		checksum.Content = []byte(packagename)
		return checksum, ""
	}

	// Our preference of picking the digest is first from "bdist" and them from "sdist"
	if checkfortag {
		pkgdigest, err := getPackageTypeDigestBDist(&packagedigests, wheeltag)
		if err == nil {
			algoType, digestValue := getHighestHashData(pkgdigest)
			checksum.Algorithm = algoType
			checksum.Value = digestValue
			return checksum, pkgdigest.DownloadURL
		}
	}

	pkgdigest, err := getPackageTypeDigestSDist(&packagedigests)
	if err == nil {
		algoType, digestValue := getHighestHashData(pkgdigest)
		checksum.Algorithm = algoType
		checksum.Value = digestValue
		return checksum, pkgdigest.DownloadURL
	}

	return checksum, ""
}

func getHighestHashData(packagedigests PackageDigest) (models.HashAlgorithm, string) {
	var algoType models.HashAlgorithm
	var digestValue string

	v := reflect.ValueOf(packagedigests.Digests)
	for _, algo := range HashAlgoPickOrder {

		f := v.FieldByName(string(algo))
		if f.IsValid() {
			algoType = algo
			digestValue = f.String()
			return algoType, digestValue
		}
	}

	return algoType, digestValue
}

func getPackageTypeDigestBDist(packagedigests *[]PackageDigest, wheeltag string) (PackageDigest, error) {
	packageType := "bdist"
	for _, pkddigest := range *packagedigests {
		if strings.Contains(strings.ToLower(pkddigest.PackageType), strings.ToLower(packageType)) &&
			strings.Contains(strings.ToLower(pkddigest.Filename), strings.ToLower(wheeltag)) {
			return pkddigest, nil
		}
	}
	return PackageDigest{}, errorPackageDigestNotFound
}

func getPackageTypeDigestSDist(packagedigests *[]PackageDigest) (PackageDigest, error) {
	packageType := "sdist"
	for _, pkddigest := range *packagedigests {
		if strings.Contains(strings.ToLower(pkddigest.PackageType), strings.ToLower(packageType)) {
			return pkddigest, nil
		}
	}
	return PackageDigest{}, errorPackageDigestNotFound
}

func fetchAndDecodePypiPackageDataJSON(packagename string, packageJsonURL string) ([]PackageDigest, error) {
	var pypipackagedata PypiPackageData
	var packagedigests []PackageDigest

	packageDataResponse, err := fetchPypiPackageDataJSON(packageJsonURL)
	if err != nil {
		return nil, err
	}
	defer packageDataResponse.Body.Close()

	jsondata, _ := ioutil.ReadAll(packageDataResponse.Body)

	err = json.Unmarshal(jsondata, &pypipackagedata)
	if err != nil {
		return nil, err
	}

	for _, url := range pypipackagedata.Urls {
		pkgDigest := PackageDigest{
			Filename:    url.Filename,
			PackageType: url.PackageType,
			Digests:     url.Digests,
			DownloadURL: url.URL,
		}
		packagedigests = append(packagedigests, pkgDigest)
	}
	return packagedigests, nil
}

func fetchPypiPackageDataJSON(packageJSONURL string) (*http.Response, error) {

	packageJSONHttpsURL := "https://" + packageJSONURL

	request, _ := http.NewRequest("GET", packageJSONHttpsURL, nil)
	request.Header.Set("Accept", "application/json")

	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}

	if response.StatusCode != http.StatusOK {
		return nil, errorPypiCouldNotFetchPkgData
	}

	return response, err
}

func makeGetRequest(packageJsonUrl string) (*http.Response, error) {
	url := "https://" + packageJsonUrl

	request, _ := http.NewRequest("GET", url, nil)
	request.Header.Set("Accept", "application/json")

	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}

	if response.StatusCode != http.StatusOK {
		return nil, errorPypiCouldNotFetchPkgData
	}

	return response, err
}
