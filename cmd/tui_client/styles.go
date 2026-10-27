package main

import "github.com/charmbracelet/lipgloss"

var (
	accentColor = lipgloss.AdaptiveColor{Light: "#1d4ed8", Dark: "#7aa2f7"}
	dimColor    = lipgloss.AdaptiveColor{Light: "#6b7280", Dark: "#737aa2"}
	onlineColor = lipgloss.AdaptiveColor{Light: "#15803d", Dark: "#9ece6a"}
	awayColor   = lipgloss.AdaptiveColor{Light: "#b45309", Dark: "#e0af68"}
	errorColor  = lipgloss.AdaptiveColor{Light: "#b91c1c", Dark: "#f7768e"}
	selfColor   = lipgloss.AdaptiveColor{Light: "#7e22ce", Dark: "#bb9af7"}

	titleStyle        = lipgloss.NewStyle().Bold(true).Foreground(accentColor)
	labelStyle        = lipgloss.NewStyle()
	focusedLabelStyle = lipgloss.NewStyle().Bold(true).Foreground(accentColor)
	selectedStyle     = lipgloss.NewStyle().Reverse(true)
	dimStyle          = lipgloss.NewStyle().Foreground(dimColor)
	statusStyle       = lipgloss.NewStyle().Foreground(accentColor)
	errorStyle        = lipgloss.NewStyle().Foreground(errorColor)
	onlineStyle       = lipgloss.NewStyle().Foreground(onlineColor)
	awayStyle         = lipgloss.NewStyle().Foreground(awayColor)
	selfStyle         = lipgloss.NewStyle().Bold(true).Foreground(selfColor)
	peerStyle         = lipgloss.NewStyle().Bold(true).Foreground(accentColor)
	groupStyle        = lipgloss.NewStyle().Bold(true)

	boxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(accentColor).
			Padding(1, 2)
	inputBoxStyle = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder(), false, false, true, false).
			BorderForeground(dimColor)

	paneStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(dimColor)
	focusedPaneStyle = paneStyle.BorderForeground(accentColor)

	activeTabStyle   = lipgloss.NewStyle().Bold(true).Foreground(accentColor).Underline(true)
	inactiveTabStyle = lipgloss.NewStyle().Foreground(dimColor)
	unreadTabStyle   = lipgloss.NewStyle().Bold(true).Foreground(awayColor)
)
