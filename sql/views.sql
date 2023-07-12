create or replace view view_repo_ownership as
select ght.id as "github_team_id"
     , ght.name as "github_team_name"
     , tr.full_name as "repo_name"
     , tr.role_name
     , tr.archived
     , gtt.team_name as "galaxies_team"
     , gtt.team_contact_email
from   github_team_repositories tr
           join github_teams ght on tr.team_id = ght.id
           left join galaxies_teams_table gtt on ght.slug = gtt.team_primary_github_team
where tr.role_name = 'admin' and tr.archived = false;

CREATE OR REPLACE FUNCTION coalesce_dates(image_creation_time text, instance_launch_time timestamp) RETURNS date
    LANGUAGE SQL
    IMMUTABLE
RETURN coalesce(cast(image_creation_time as date), cast(instance_launch_time as date));

create or replace view view_old_ec2_instances as
select  ac.id as account_id
     , ac.name as account_name
     , ec2.instance_id
     , ec2.state ->> 'Name' as state
     , ec2.tags ->> 'Stack' as stack
     , ec2.tags ->> 'Stage' as stage
     , ec2.tags ->> 'App' as app
     , ec2.tags ->> 'gu:repo' as repo
     , ec2.region
     , coalesce_dates(img.creation_date, ec2.launch_time) as creation_or_launch_time
from aws_ec2_instances ec2
         left join aws_ec2_images img on ec2.image_id = img.image_id
         left join aws_accounts ac on ec2.account_id = ac.id
where (
        coalesce_dates(img.creation_date, ec2.launch_time) is null
        or coalesce_dates(img.creation_date, ec2.launch_time) < NOW() - INTERVAL '30 days'
    )
  and ec2.state ->> 'Name' = 'running';

create or replace view view_running_instances as
select distinct
    accts.name,
    instances.tags ->> 'App' as app,
    instances.image_id,
    instances.instance_id,
    CASE
        WHEN images.tags ->> 'BuiltBy'='amigo' THEN true
        ELSE false
    END as built_by_amigo
from
    aws_ec2_instances instances
        left join aws_ec2_images images on instances.image_id = images.image_id
        left join aws_organizations_accounts accts on instances.account_id = accts.id
where
            instances.state ->> 'Name' = 'running';

/*
 This view destructures snyk_projects on the tags field, creating a layout that is easier to query.

 It's shape is:
   id | org_id | name | repo | commit
 */

--| project1 | key:commit, value:somecommithash |
--| project1 | key:repo, value:guardian/somerepo |
with all_tags as (
  select id, jsonb_array_elements(tags) as tags
  from snyk_projects
),

 -- | project-1 | somecommithash |
projects_with_hashes as (
  select id, tags ->> 'value' as hash
  from all_tags
  where tags ->> 'key' = 'commit'
),

-- | project-1 | guardian/somerepo |
projects_with_repos as (
  select id, tags ->> 'value' as repo
  from all_tags
  where tags ->> 'key' = 'repo'
)

create or replace view view_snyk_project_tags as select
  p.id, p.org_id, p.name, r.repo, h.hash
from
  snyk_projects p
  left join projects_with_hashes h on p.id = h.id
  left join projects_with_repos r on p.id = r.id
order by h.hash
