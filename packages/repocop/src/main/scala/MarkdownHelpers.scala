package com.gu.repocop

import Rules.RepoRule
object MarkdownHelpers {

  def createPage(rules: List[Rules.RepoRule]): String = {
    val preamble: String =
      """
        |## Repo Rules
        |
        |This table is autogenerated from the Rules object as a human-readable reference to our GitHub best practices.
        |
        |""".stripMargin

    preamble + generateMarkdownTable(rules)
  }
  private def generateMarkdownTable(rules: List[Rules.RepoRule]): String = {
    val repoRules: List[(String, (String, String))] = rules
      .map(_.toString)
      .zip(rules.map(r => (r.violationMessage, r.ruleJustification)))
    val tableHeader =
      "| Rule Name | Violation Message | Rule Justification |\n|---|---|---|\n"
    val tableContent =
      repoRules.map(flattenTuple).map(tupleToTable).reduce(_ + _)
    tableHeader + tableContent
  }

  private def flattenTuple(
      nested: (String, (String, String))
  ): (String, String, String) = {
    nested match
      case (x, (y, z)) => (x, y, z)
  }

  private def tupleToTable(t: (String, String, String)) =
    s"| ${t._1} | ${t._2} | ${t._3} |\n"

}
