// Package blob is the Go SDK for Upstash Blob: a [Bucket] client for server-side reads and writes,
// and an [UploadHandler] that serves the upload protocol of @upstash/blob/browser and
// @upstash/blob/react, so a browser uploads straight to storage through a Go backend.
//
// Every failure the SDK reports on purpose is an [*Error] with a Code from a closed list.
package blob
