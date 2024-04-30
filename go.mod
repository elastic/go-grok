module github.com/elastic/go-grok

go 1.21.9

replace github.com/elastic/go-grok/dev-tools/mage => ./devtools/mage

require (
	github.com/elastic/go-licenser v0.4.1
	github.com/magefile/mage v1.15.0
	go.elastic.co/go-licence-detector v0.6.0
	golang.org/x/tools v0.13.0
)

require (
	github.com/cyphar/filepath-securejoin v0.2.2 // indirect
	github.com/gobuffalo/here v0.6.0 // indirect
	github.com/google/licenseclassifier v0.0.0-20200402202327-879cb1424de0 // indirect
	github.com/karrick/godirwalk v1.15.6 // indirect
	github.com/markbates/pkger v0.17.0 // indirect
	github.com/pkg/errors v0.8.1 // indirect
	github.com/sergi/go-diff v1.1.0 // indirect
	github.com/stretchr/testify v1.9.0 // indirect
	golang.org/x/mod v0.17.0 // indirect
	golang.org/x/sync v0.7.0 // indirect
	golang.org/x/sys v0.12.0 // indirect
)
