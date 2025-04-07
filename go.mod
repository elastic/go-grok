module github.com/elastic/go-grok

go 1.22.0

toolchain go1.24.2

replace github.com/elastic/go-grok/dev-tools/mage => ./devtools/mage

require (
	github.com/elastic/go-licenser v0.4.1
	github.com/magefile/mage v1.15.0
	github.com/stretchr/testify v1.10.0
	github.com/wasilibs/go-re2 v1.10.0
	go.elastic.co/go-licence-detector v0.6.0
	golang.org/x/tools v0.13.0
)

require (
	github.com/cyphar/filepath-securejoin v0.2.4 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/gobuffalo/here v0.6.0 // indirect
	github.com/google/licenseclassifier v0.0.0-20200402202327-879cb1424de0 // indirect
	github.com/karrick/godirwalk v1.15.6 // indirect
	github.com/markbates/pkger v0.17.0 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/sergi/go-diff v1.1.0 // indirect
	github.com/tetratelabs/wazero v1.9.0 // indirect
	github.com/wasilibs/wazero-helpers v0.0.0-20240620070341-3dff1577cd52 // indirect
	golang.org/x/mod v0.17.0 // indirect
	golang.org/x/sync v0.7.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
