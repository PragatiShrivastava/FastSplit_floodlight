package net.floodlightcontroller.mobilityprotocols;

public class DFS
{
	public void dfs(int[][] adjacency_matrix, int source,
			int destination, int splength, int number_of_nodes, int[] path) {
		// TODO Auto-generated method stub
		if(number_of_nodes != 0)
		{
			findPath(source,0, splength, destination,adjacency_matrix, number_of_nodes, path);
		}
		
	}

	private Boolean findPath(int root, int length, int splength, int destination,
			int[][] adjacency_matrix, int number_of_nodes, int path[]) {
		// TODO Auto-generated method stub
		Boolean result;
		if(length > splength)
			return false;
		if(root == destination)
		{
			System.out.println("finddddd "+ "len="+ length +"root="+ root);
			path[length]= root;
			return true;
		}
		for (int i=1; i<= number_of_nodes; i++)
		{
			if(i!=root)
			{
				if(adjacency_matrix[root][i] != 0 )
				{
					result= findPath(i, length+1, splength, destination, adjacency_matrix, number_of_nodes, path);
					if(result == true)
					{
						path[length]= root;
						return true;
					}
				}
			}
			
		}
		return false;
			
	}	
}