module github.com/tjfoc/gmsm

go 1.15

require (
	github.com/emmansun/gmsm v0.11.5
	golang.org/x/crypto v0.21.0
)

replace github.com/emmansun/gmsm => github.com/easyops-cn/emmansun-gmsm hack // TODO: update test certs and remove this hack
