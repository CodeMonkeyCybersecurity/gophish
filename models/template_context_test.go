package models

import (
	"fmt"

	check "gopkg.in/check.v1"
)

type mockTemplateContext struct {
	URL         string
	FromAddress string
}

func (m mockTemplateContext) getFromAddress() string {
	return m.FromAddress
}

func (m mockTemplateContext) getBaseURL() string {
	return m.URL
}

func (s *ModelsSuite) TestNewTemplateContext(c *check.C) {
	r := Result{
		BaseRecipient: BaseRecipient{
			FirstName: "Foo",
			LastName:  "Bar",
			Email:     "foo@bar.com",
		},
		RId: "1234567",
	}
	ctx := mockTemplateContext{
		URL:         "http://example.com",
		FromAddress: "From Address <from@example.com>",
	}
	expected := PhishingTemplateContext{
		URL:           fmt.Sprintf("%s?rid=%s", ctx.URL, r.RId),
		BaseURL:       ctx.URL,
		BaseRecipient: r.BaseRecipient,
		TrackingURL:   fmt.Sprintf("%s/track?rid=%s", ctx.URL, r.RId),
		From:          "From Address",
		RId:           r.RId,
	}
	expected.Tracker = "<img alt='' style='display: none' src='" + expected.TrackingURL + "'/>"
	got, err := NewPhishingTemplateContext(ctx, r.BaseRecipient, r.RId)
	c.Assert(err, check.Equals, nil)
	c.Assert(got, check.DeepEquals, expected)
}

func (s *ModelsSuite) TestSanitizeHTMLForDisplay(c *check.C) {
	testCases := []struct {
		input    string
		expected string
	}{
		{
			input:    `<script>alert('xss')</script>`,
			expected: `&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;`,
		},
		{
			input:    `<img src=x onerror="alert(1)">`,
			expected: `&lt;img src=x onerror=&#34;alert(1)&#34;&gt;`,
		},
		{
			input:    `Hello World`,
			expected: `Hello World`,
		},
		{
			input:    `Tom & Jerry`,
			expected: `Tom &amp; Jerry`,
		},
	}

	for _, tc := range testCases {
		result := SanitizeHTMLForDisplay(tc.input)
		c.Assert(result, check.Equals, tc.expected)
	}
}

func (s *ModelsSuite) TestDetectXSSPatterns(c *check.C) {
	testCases := []struct {
		input        string
		shouldDetect bool
	}{
		{input: `<script>alert(1)</script>`, shouldDetect: true},
		{input: `<img src=x onerror=alert(1)>`, shouldDetect: true},
		{input: `javascript:alert(1)`, shouldDetect: true},
		{input: `Hello World`, shouldDetect: false},
		{input: `<p>This is a paragraph</p>`, shouldDetect: false},
	}

	for _, tc := range testCases {
		detected := DetectXSSPatterns(tc.input)
		c.Assert(detected, check.Equals, tc.shouldDetect)
	}
}

func (s *ModelsSuite) TestValidateAndSanitizeTemplateName(c *check.C) {
	testCases := []struct {
		input       string
		shouldError bool
		expectedErr string
	}{
		{input: "My Template", shouldError: false},
		{input: "<script>alert(1)</script>", shouldError: true, expectedErr: "potentially malicious content"},
		{input: "", shouldError: true, expectedErr: "cannot be empty"},
	}

	for _, tc := range testCases {
		_, err := ValidateAndSanitizeTemplateName(tc.input)
		if tc.shouldError {
			c.Assert(err, check.NotNil)
			c.Assert(err.Error(), check.Matches, ".*"+tc.expectedErr+".*")
		} else {
			c.Assert(err, check.IsNil)
		}
	}
}
