module github.com/tjfoc/gmsm

go 1.15

require (
	github.com/emmansun/gmsm v0.11.3
	golang.org/x/crypto v0.0.0-20220214200702-86341886e292
)

replace github.com/emmansun/gmsm => github.com/easyops-cn/emmansun-gmsm hack // TODO: update test certs and remove this hack
